package user

import (
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg"
	harboruser "github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg/user"
	"github.com/sirupsen/logrus"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/pkg/errors"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/parse"
	"github.com/rancher/norman/types"
	"github.com/rancher/rancher/pkg/auth/providerrefresh"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/settings"
	"golang.org/x/crypto/bcrypt"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (h *Handler) UserFormatter(apiContext *types.APIContext, resource *types.RawResource) {
	resource.AddAction(apiContext, "setpassword")

	if canRefresh := h.userCanRefresh(apiContext); canRefresh {
		resource.AddAction(apiContext, "refreshauthprovideraccess")
	}
}

func (h *Handler) CollectionFormatter(apiContext *types.APIContext, collection *types.GenericCollection) {
	collection.AddAction(apiContext, "changepassword")
	if canRefresh := h.userCanRefresh(apiContext); canRefresh {
		collection.AddAction(apiContext, "refreshauthprovideraccess")
	}
}

type Handler struct {
	UserClient               v3.UserInterface
	GlobalRoleBindingsClient v3.GlobalRoleBindingInterface
	UserAuthRefresher        providerrefresh.UserAuthRefresher
}

func (h *Handler) Actions(actionName string, action *types.Action, apiContext *types.APIContext) error {
	switch actionName {
	case "changepassword":
		if err := h.changePassword(actionName, action, apiContext); err != nil {
			return err
		}
	case "setpassword":
		if err := h.setPassword(actionName, action, apiContext); err != nil {
			return err
		}
	case "refreshauthprovideraccess":
		if err := h.refreshAttributes(actionName, action, apiContext); err != nil {
			return err
		}
	default:
		return errors.Errorf("bad action %v", actionName)
	}

	if !strings.EqualFold(settings.FirstLogin.Get(), "false") {
		if err := settings.FirstLogin.Set("false"); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) changePassword(actionName string, action *types.Action, request *types.APIContext) error {
	actionInput, err := parse.ReadBody(request.Request)
	if err != nil {
		return err
	}

	store := request.Schema.Store
	if store == nil {
		return errors.New("no user store available")
	}

	userID := request.Request.Header.Get("Impersonate-User")
	if userID == "" {
		return errors.New("can't find user")
	}

	currentPass, ok := actionInput["currentPassword"].(string)
	if !ok || len(currentPass) == 0 {
		return httperror.NewAPIError(httperror.InvalidBodyContent, "must specify current password")
	}

	newPass, ok := actionInput["newPassword"].(string)
	if !ok || len(newPass) == 0 {
		return httperror.NewAPIError(httperror.InvalidBodyContent, "invalid new password")
	}

	user, err := h.UserClient.Get(userID, v1.GetOptions{})
	if err != nil {
		return err
	}

	if err := validatePassword(user.Username, newPass, settings.PasswordMinLength.GetInt()); err != nil {
		return httperror.NewAPIError(httperror.InvalidBodyContent, err.Error())
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPass)); err != nil {
		return httperror.NewAPIError(httperror.InvalidBodyContent, "invalid current password")
	}

	newPassHash, err := HashPasswordString(newPass)
	if err != nil {
		return err
	}

	// 旧密码
	oldEdgespherePW := user.EdgespherePW

	user.Password = newPassHash
	user.MustChangePassword = false
	// 保存新密码
	encryptPassword, err := pkg.EncryptString(pkg.Key, newPass)
	if err != nil {
		logrus.Errorf("用户%v，密码加密失败：%v", user.Username, err.Error())
	}
	user.EdgespherePW = encryptPassword
	user, err = h.UserClient.Update(user)
	if err != nil {
		return err
	}

	// 更新harbor密码
	//authUsername := request.Request.Header.Get("Impersonate-Extra-Username")
	authUsername := user.Username
	logrus.Infof("发送指令用户：%v", authUsername)
	if err = changeHarborPassword(authUsername, oldEdgespherePW, newPass); err != nil {
		logrus.Errorf("制品库用户%v, 更新密码失败:%v", user.Username, err.Error())
	}

	return nil
}

func (h *Handler) setPassword(actionName string, action *types.Action, request *types.APIContext) error {
	actionInput, err := parse.ReadBody(request.Request)
	if err != nil {
		return err
	}

	store := request.Schema.Store
	if store == nil {
		return errors.New("no user store available")
	}

	userData, err := store.ByID(request, request.Schema, request.ID)
	if err != nil {
		return err
	}

	newPass, ok := actionInput["newPassword"].(string)
	if !ok || len(newPass) == 0 {
		return errors.New("Invalid password")
	}

	username := userData[client.UserFieldUsername].(string)

	if err := validatePassword(username, newPass, settings.PasswordMinLength.GetInt()); err != nil {
		return httperror.NewAPIError(httperror.InvalidBodyContent, err.Error())
	}

	// 保存新密码
	encryptPassword, err := pkg.EncryptString(pkg.Key, newPass)
	if err != nil {
		logrus.Errorf("用户%v，密码加密失败：%v", username, err.Error())
	}
	userData[client.UserFieldEdgespherePW] = encryptPassword

	userData[client.UserFieldPassword] = newPass
	if err := hashPassword(userData); err != nil {
		return err
	}
	userData[client.UserFieldMustChangePassword] = false
	delete(userData, "me")

	userData, err = store.Update(request, request.Schema, userData, request.ID)
	if err != nil {
		return err
	}

	request.WriteResponse(http.StatusOK, userData)

	// 更新harbor密码
	if err = setHarborPassword(h, request, username, newPass); err != nil {
		logrus.Errorf("制品库用户%v, 更新失败:%v", username, err.Error())
	}
	return nil
}

// 修改 harbor 密码，用于 changePassword
func changeHarborPassword(authUsername, encryptAuthPassword, newPass string) error {
	// 获取密码
	authPassword, err := getHarborChangePassword(authUsername, encryptAuthPassword)
	if err != nil {
		logrus.Infof("获取密码失败: %v", err.Error())
		return err
	}

	// 修改密码
	if err := harboruser.ChangeCurrentPassword(authUsername, authPassword, newPass); err != nil {
		return err
	}

	return nil
}

// 修改 harbor 密码，用于 setPassword
func setHarborPassword(h *Handler, request *types.APIContext, username, newPass string) error {
	// 获取当前用户
	authUsername := request.Request.Header.Get("Impersonate-Extra-Username")
	if len(authUsername) == 0 {
		return errors.New("There was an error authorizing the user")
	}
	logrus.Infof("发送指令用户：%v", authUsername)

	// 获取密码
	userID := request.Request.Header.Get("Impersonate-User")
	if userID == "" {
		return errors.New("can't find user")
	}

	authPassword, err := getHarborSetPassword(h, userID)
	if err != nil {
		logrus.Infof("获取密码失败: %v", err.Error())
		return err
	}

	if authUsername == "admin" && authPassword == "" { // 初次登录
		authPassword = pkg.HarborAdminPassword
	}

	// 修改密码
	if err := harboruser.ChangePassword(authUsername, authPassword, username, newPass); err != nil {
		return err
	}

	return nil
}

// 获取 harbor user密码, 用于 changePassword
func getHarborChangePassword(authUsername, encryptAuthPassword string) (string, error) {
	if authUsername == "admin" && encryptAuthPassword == "" { // 初次登录
		return pkg.HarborEdgesphereAdminPassword, nil
	}
	// 解码
	authPassword, err := pkg.DecryptString(pkg.Key, encryptAuthPassword)
	if err != nil {
		logrus.Errorf("解码失败: %v", err.Error())
		return "", err
	}

	return authPassword, nil
}

// 获取 harbor user密码, 用于 setPassword
func getHarborSetPassword(h *Handler, userID string) (string, error) {
	authUser, err := h.UserClient.Get(userID, v1.GetOptions{})
	if err != nil {
		return "", err
	}

	encryptAuthPassword := authUser.EdgespherePW
	if len(encryptAuthPassword) == 0 {
		return "", nil
	}

	// 解码
	authPassword, err := pkg.DecryptString(pkg.Key, encryptAuthPassword)
	if err != nil {
		logrus.Errorf("解码失败: %v", err.Error())
		return "", err
	}

	return authPassword, nil
}

func (h *Handler) refreshAttributes(actionName string, action *types.Action, request *types.APIContext) error {
	canRefresh := h.userCanRefresh(request)

	if !canRefresh {
		return errors.New("Not Allowed")
	}

	if request.ID != "" {
		h.UserAuthRefresher.TriggerUserRefresh(request.ID, true)
	} else {
		h.UserAuthRefresher.TriggerAllUserRefresh()
	}

	request.WriteResponse(http.StatusOK, nil)
	return nil
}

func (h *Handler) userCanRefresh(request *types.APIContext) bool {
	return request.AccessControl.CanDo(v3.UserGroupVersionKind.Group, v3.UserResource.Name, "create", request, nil, request.Schema) == nil
}

// validatePassword will ensure a password is at least the minimum required length in runes, and that the username and password do not match.
func validatePassword(user string, pass string, minPassLen int) error {
	hasLower := regexp.MustCompile(`[a-z]`)
	hasUpper := regexp.MustCompile(`[A-Z]`)
	hasNumber := regexp.MustCompile(`[0-9]`)
	if utf8.RuneCountInString(pass) < minPassLen || !(hasLower.MatchString(pass) && hasUpper.MatchString(pass) && hasNumber.MatchString(pass)) {
		return errors.Errorf("Password must be at least %v characters with at least 1 uppercase letter, 1 lowercase letter and 1 number", minPassLen)
	}

	if user == pass {
		return errors.New("Password cannot be the same as username")
	}

	return nil
}

func validateUsername(username string) error {
	maxPasslen := 255
	if utf8.RuneCountInString(username) > maxPasslen {
		return errors.Errorf("Username must be at most %v characters", maxPasslen)
	}

	illegalChar := []string{",", "~", "#", "$", "%"}
	if IsContainIllegalChar(username, illegalChar) {
		return errors.Errorf("Username contains illegal characters: %v", illegalChar)
	}
	return nil
}

// IsContainIllegalChar ...
func IsContainIllegalChar(s string, illegalChar []string) bool {
	for _, c := range illegalChar {
		if strings.Contains(s, c) {
			return true
		}
	}
	return false
}
