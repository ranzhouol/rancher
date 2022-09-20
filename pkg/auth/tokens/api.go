package tokens

import (
	"context"
	"net/http"

	normanapi "github.com/rancher/norman/api"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	managementSchema "github.com/rancher/rancher/pkg/schemas/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
)

const (
	CookieName      = "R_SESS"
	AuthHeaderName  = "Authorization"
	AuthValuePrefix = "Bearer"
	BasicAuthPrefix = "Basic"
	CSRFCookie      = "CSRF"
)

var crdVersions = []*types.APIVersion{
	&managementSchema.Version,
}

type ServerOption func(server *normanapi.Server)

//1、直接调用的是normanapi
func NewAPIHandler(ctx context.Context, apiContext *config.ScaledContext, opts ...ServerOption) (http.Handler, error) {

	api := &tokenAPI{
		mgr: NewManager(ctx, apiContext),
	}

	schemas := types.NewSchemas().AddSchemas(managementSchema.TokenSchemas)
	schema := schemas.Schema(&managementSchema.Version, client.TokenType)
	schema.CollectionActions = map[string]types.Action{
		"logout": {},
	}
	// 1、token 的相关操作，这里是因为直接定义了所有的handler 因此不在需要使用默认的方法，所以没有初始化store
	// 2、token的CRD的初始化，在是用户的时候已经初始化过了，因此这里也没有进行CRD 的初始化
	schema.ActionHandler = api.tokenActionHandler
	schema.ListHandler = api.tokenListHandler
	schema.CreateHandler = api.tokenCreateHandler
	schema.DeleteHandler = api.tokenDeleteHandler

	server := normanapi.NewAPIServer()
	if err := server.AddSchemas(schemas); err != nil {
		return nil, err
	}

	for _, opt := range opts {
		opt(server)
	}

	return server, nil
}

type tokenAPI struct {
	mgr *Manager
}

//自定义action，这里是normanapi的封装
func (t *tokenAPI) tokenActionHandler(actionName string, action *types.Action, request *types.APIContext) error {
	logrus.Debugf("TokenActionHandler called for action %v", actionName)
	//1、主动退出会把token 从etcd中删除
	if actionName == "logout" {
		return t.mgr.logout(actionName, action, request)
	}
	return httperror.NewAPIError(httperror.ActionNotAvailable, "")
}

func (t *tokenAPI) tokenCreateHandler(request *types.APIContext, _ types.RequestHandler) error {
	logrus.Debugf("TokenCreateHandler called")
	// token 创建，会把token 存放到etcd中
	return t.mgr.deriveToken(request)
}

func (t *tokenAPI) tokenListHandler(request *types.APIContext, _ types.RequestHandler) error {
	logrus.Debugf("TokenListHandler called")
	if request.ID != "" {
		return t.mgr.getTokenFromRequest(request)
	}
	return t.mgr.listTokens(request)
}

func (t *tokenAPI) tokenDeleteHandler(request *types.APIContext, _ types.RequestHandler) error {
	logrus.Debugf("TokenDeleteHandler called")
	return t.mgr.removeToken(request)
}
