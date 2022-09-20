package api

import (
	"context"
	"net/http"

	normanapi "github.com/rancher/norman/api"
	"github.com/rancher/norman/pkg/subscribe"
	"github.com/rancher/norman/store/crd"
	"github.com/rancher/norman/types"
	"github.com/rancher/rancher/pkg/api/scheme"
	"github.com/rancher/rancher/pkg/auth/api/user"
	"github.com/rancher/rancher/pkg/auth/principals"
	"github.com/rancher/rancher/pkg/auth/providerrefresh"
	"github.com/rancher/rancher/pkg/auth/providers"
	"github.com/rancher/rancher/pkg/auth/requests"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	managementschema "github.com/rancher/rancher/pkg/schemas/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/types/config"
)

func Setup(ctx context.Context, clusterRouter requests.ClusterRouter, scaledContext *config.ScaledContext, schemas *types.Schemas) {
	//1、定义principals相关的handler
	principals.Schema(ctx, clusterRouter, scaledContext, schemas)
	providers.SetupAuthConfig(ctx, scaledContext, schemas)
	//2、设置用户的store，为了使用默认的api 接口方法，schemas.Schema(&managementschema.Version, client.UserType)取出指定的schema
	user.SetUserStore(schemas.Schema(&managementschema.Version, client.UserType), scaledContext)
	User(ctx, schemas, scaledContext)
}

func User(ctx context.Context, schemas *types.Schemas, management *config.ScaledContext) {
	//1、定义User的相关处理函数
	schema := schemas.Schema(&managementschema.Version, client.UserType)
	//2、构建user handler的处理函数
	handler := &user.Handler{
		UserClient:               management.Management.Users(""),
		GlobalRoleBindingsClient: management.Management.GlobalRoleBindings(""),
		UserAuthRefresher:        providerrefresh.NewUserAuthRefresher(ctx, management),
	}
	//3、添加自定义的action，对相关操作进行赋值，主要包括对密码修改等相关操作
	schema.Formatter = handler.UserFormatter
	schema.CollectionFormatter = handler.CollectionFormatter
	schema.ActionHandler = handler.Actions
}

func NewNormanServer(ctx context.Context, clusterRouter requests.ClusterRouter, scaledContext *config.ScaledContext) (http.Handler, error) {
	//1、构建路由表
	schemas, err := newSchemas(ctx, scaledContext)
	if err != nil {
		return nil, err
	}
	//2、装载相关配置
	Setup(ctx, clusterRouter, scaledContext, schemas)

	server := normanapi.NewAPIServer()
	if err := server.AddSchemas(schemas); err != nil {
		return nil, err
	}
	return server, nil
}

func newSchemas(ctx context.Context, apiContext *config.ScaledContext) (*types.Schemas, error) {
	//1、这里是使用normon 固定用法
	schemas := types.NewSchemas()
	schemas.AddSchemas(managementschema.AuthSchemas)
	//2、构建路由schema，这里没有创建CRD 和创建store，这些操作都在下面
	subscribe.Register(&managementschema.Version, schemas)
	//3、创建对应的CRD资源，都是和用户相关的类型
	factory := &crd.Factory{ClientGetter: apiContext.ClientGetter}
	factory.BatchCreateCRDs(ctx, config.ManagementStorageContext, scheme.Scheme, schemas, &managementschema.Version,
		client.AuthConfigType,
		client.GroupMemberType,
		client.GroupType,
		client.TokenType,
		client.UserAttributeType,
		client.UserType,
	)

	return schemas, factory.BatchWait()
}
