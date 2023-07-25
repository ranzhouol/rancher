package user

import (
	harboruser "github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg/user"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/store/transform"
	"github.com/rancher/norman/types"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/rancher/pkg/user"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"k8s.io/client-go/tools/cache"
)

const (
	userByUsernameIndex    = "auth.management.cattle.io/user-by-username"
	userByDescriptionIndex = "auth.management.cattle.io/user-by-description"
)

type userStore struct {
	types.Store
	mu          sync.Mutex
	userIndexer cache.Indexer
	userManager user.Manager
}

func SetUserStore(schema *types.Schema, mgmt *config.ScaledContext) {
	userInformer := mgmt.Management.Users("").Controller().Informer()
	userIndexers := map[string]cache.IndexFunc{
		userByUsernameIndex:    userByUsername,
		userByDescriptionIndex: userByDescription,
	}
	userInformer.AddIndexers(userIndexers)

	store := &userStore{
		Store:       schema.Store,
		mu:          sync.Mutex{},
		userIndexer: userInformer.GetIndexer(),
		userManager: mgmt.UserManager,
	}

	t := &transform.Store{
		Store: store,
		Transformer: func(apiContext *types.APIContext, schema *types.Schema, data map[string]interface{}, opt *types.QueryOptions) (map[string]interface{}, error) {
			// filter system users out of the api
			if princIds, ok := data[client.UserFieldPrincipalIDs].([]interface{}); ok {
				for _, p := range princIds {
					pid, _ := p.(string)
					if strings.HasPrefix(pid, "system://") {
						if opt != nil && opt.Options["ByID"] == "true" {
							return nil, httperror.NewAPIError(httperror.NotFound, "resource not found")
						}
						return nil, nil
					}
				}
			}

			// set "me" field on user
			userID := apiContext.Request.Header.Get("Impersonate-User")
			if userID != "" {
				id, ok := data[types.ResourceFieldID].(string)
				if ok {
					if id == userID {
						data["me"] = "true"
					}
				}
			}

			return data, nil
		},
	}
	// 这里指定了schema的store ，因此在handler的时候，首先掉用的是这个Create
	schema.Store = t
}

func userByUsername(obj interface{}) ([]string, error) {
	u, ok := obj.(*v3.User)
	if !ok {
		return []string{}, nil
	}

	return []string{u.Username}, nil
}

func userByDescription(obj interface{}) ([]string, error) {
	u, ok := obj.(*v3.User)
	if !ok {
		return []string{}, nil
	}

	return []string{u.Description}, nil
}

func hashPassword(data map[string]interface{}) error {
	pass, ok := data[client.UserFieldPassword].(string)
	if !ok {
		return errors.New("password not a string")
	}
	hashed, err := HashPasswordString(pass)
	if err != nil {
		return err
	}
	data[client.UserFieldPassword] = string(hashed)

	return nil
}

func HashPasswordString(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.Wrap(err, "problem encrypting password")
	}
	return string(hash), nil
}

func (s *userStore) Create(apiContext *types.APIContext, schema *types.Schema, data map[string]interface{}) (map[string]interface{}, error) {
	username, ok := data[client.UserFieldUsername].(string)
	if !ok {
		return nil, errors.New("invalid username")
	}

	password, ok := data[client.UserFieldPassword].(string)
	if !ok {
		return nil, errors.New("invalid password")
	}

	if err := s.validateDescription(data); err != nil {
		return nil, err
	}

	if err := validateUsername(username); err != nil {
		return nil, httperror.NewAPIError(httperror.InvalidBodyContent, err.Error())
	}

	if err := validatePassword(username, password, settings.PasswordMinLength.GetInt()); err != nil {
		return nil, httperror.NewAPIError(httperror.InvalidBodyContent, err.Error())
	}

	if err := hashPassword(data); err != nil {
		return nil, err
	}

	created, err := s.create(apiContext, schema, data)
	if err != nil {
		return nil, err
	}

Tries:
	for x := 0; x < 3; x++ {
		if id, ok := created[types.ResourceFieldID].(string); ok {
			time.Sleep(time.Duration((x+1)*100) * time.Millisecond)

			created, err = s.ByID(apiContext, schema, id)
			if err != nil {
				logrus.Warnf("error while getting user: %v", err)
				continue
			}

			var principalIDs []interface{}
			if pids, ok := created[client.UserFieldPrincipalIDs].([]interface{}); ok {
				principalIDs = pids
			}

			for _, pid := range principalIDs {
				if pidString, ok := pid.(string); ok {
					if strings.HasPrefix(pidString, "local://") {
						break Tries
					}
				}
			}

			created[client.UserFieldPrincipalIDs] = append(principalIDs, "local://"+id)
			created, err = s.Update(apiContext, schema, created, id)
			if err != nil {
				if httperror.IsConflict(err) {
					continue
				}

				logrus.Warnf("error while updating user: %v", err)
				break
			}
			break
		}
	}

	delete(created, client.UserFieldPassword)

	// 创建 harbor 用户
	if err := harboruser.Create(username, password, username+"@qq.com", username); err != nil {
		logrus.Errorf("创建harbor用户%v失败: %v", username, err.Error())
	}
	//created["annotations"].(map[string]interface{})["edgesphere/harbor-users"] = "true"
	//logrus.Info("创建4的created: ", created)
	return created, nil
}

func (s *userStore) validateDescription(data map[string]interface{}) error {
	description, ok := data[client.UserFieldDescription].(string)
	if !ok {
		return errors.New("invalid description")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.userIndexer.ByIndex(userByDescriptionIndex, description)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return httperror.NewFieldAPIError(httperror.NotUnique, "description", "Description is already in use.")
	}
	return nil
}

func (s *userStore) create(apiContext *types.APIContext, schema *types.Schema, data map[string]interface{}) (map[string]interface{}, error) {
	username, ok := data[client.UserFieldUsername].(string)
	if !ok {
		return nil, errors.New("invalid username")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.userIndexer.ByIndex(userByUsernameIndex, username)
	if err != nil {
		return nil, err
	}
	if len(users) > 0 {
		return nil, httperror.NewFieldAPIError(httperror.NotUnique, "username", "Username is already in use.")
	}

	return s.Store.Create(apiContext, schema, data)
}

func (s *userStore) Update(apiContext *types.APIContext, schema *types.Schema, data map[string]interface{}, id string) (map[string]interface{}, error) {
	currentUser, err := getUser(apiContext)
	if err != nil {
		return nil, err
	}

	willBeInactive := false
	if val, ok := data[client.UserFieldEnabled].(bool); ok {
		willBeInactive = !val
	}

	if currentUser == id && willBeInactive {
		return nil, httperror.NewAPIError(httperror.InvalidAction, "You cannot deactivate yourself")
	}

	return s.Store.Update(apiContext, schema, data, id)
}

func (s *userStore) Delete(apiContext *types.APIContext, schema *types.Schema, id string) (map[string]interface{}, error) {
	currentUser, err := getUser(apiContext)
	if err != nil {
		return nil, err
	}

	if currentUser == id {
		return nil, httperror.NewAPIError(httperror.InvalidAction, "You cannot delete yourself")
	}

	authUsername := apiContext.Request.Header.Get("Impersonate-Extra-Username")
	data, err := s.Store.ByID(apiContext, schema, id)
	if err != nil {
		logrus.Error(err.Error())
	}
	username := data["username"]
	logrus.Infof("发送指令用户：%v", authUsername)
	logrus.Infof("指令删除用户：%v", username)
	// 删除harbor用户
	if err := harboruser.Delete(username.(string)); err != nil {
		logrus.Errorf("制品库用户 %v, 删除失败: %v", username, err.Error())
	}
	return s.Store.Delete(apiContext, schema, id)
}

func getUser(apiContext *types.APIContext) (string, error) {
	user := apiContext.Request.Header.Get("Impersonate-User")
	if user == "" {
		return "", httperror.NewAPIError(httperror.ServerError, "There was an error authorizing the user")
	}

	return user, nil
}
