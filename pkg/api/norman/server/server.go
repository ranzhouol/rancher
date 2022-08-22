package server

import (
	"context"
	"net/http"

	responsewriter "github.com/rancher/apiserver/pkg/middleware"
	"github.com/rancher/norman/api/builtin"
	"github.com/rancher/norman/pkg/subscribe"
	"github.com/rancher/rancher/pkg/api/norman"
	"github.com/rancher/rancher/pkg/api/norman/server/managementstored"
	"github.com/rancher/rancher/pkg/api/norman/server/userstored"
	"github.com/rancher/rancher/pkg/clustermanager"
	"github.com/rancher/rancher/pkg/controllers/managementapi"
	clusterSchema "github.com/rancher/rancher/pkg/schemas/cluster.cattle.io/v3"
	managementSchema "github.com/rancher/rancher/pkg/schemas/management.cattle.io/v3"
	projectSchema "github.com/rancher/rancher/pkg/schemas/project.cattle.io/v3"
	"github.com/rancher/rancher/pkg/types/config"
)

func New(ctx context.Context, scaledContext *config.ScaledContext, clusterManager *clustermanager.Manager,
	k8sProxy http.Handler, localClusterEnabled bool) (http.Handler, error) {
	//1、调用的是norman的方法，注册Schema之后，可以通过对外暴露服务进行访问，这些是针对CRD资源，rancher封装的api接口
	subscribe.Register(&builtin.Version, scaledContext.Schemas)
	subscribe.Register(&managementSchema.Version, scaledContext.Schemas)
	subscribe.Register(&clusterSchema.Version, scaledContext.Schemas)
	subscribe.Register(&projectSchema.Version, scaledContext.Schemas)
	//2、管理存储安装
	if err := managementstored.Setup(ctx, scaledContext, clusterManager, k8sProxy, localClusterEnabled); err != nil {
		return nil, err
	}

	if err := userstored.Setup(ctx, scaledContext, clusterManager, k8sProxy); err != nil {
		return nil, err
	}
	//2、创建norman的api server
	server, err := norman.NewServer(scaledContext.Schemas)
	if err != nil {
		return nil, err
	}
	server.AccessControl = scaledContext.AccessControl
	//3、managementapi 注册controller
	if err := managementapi.Register(ctx, scaledContext, clusterManager, server); err != nil {
		return nil, err
	}

	chainGzip := responsewriter.Chain{responsewriter.Gzip, responsewriter.ContentType}
	return chainGzip.Handler(server), nil
}
