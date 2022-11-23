package dashboardapi

import (
	"context"

	"github.com/rancher/rancher/pkg/controllers/dashboardapi/feature"
	"github.com/rancher/rancher/pkg/controllers/dashboardapi/settings"
	"github.com/rancher/rancher/pkg/wrangler"
)

func Register(ctx context.Context, wrangler *wrangler.Context) error {
	//  feature controller 注册
	feature.Register(ctx, wrangler.Mgmt.Feature())
	// helm 相关
	//helm.RegisterReposForFollowers(ctx, wrangler.Core.Secret().Cache(), wrangler.Catalog.ClusterRepo())
	return settings.Register(wrangler.Mgmt.Setting())
}
