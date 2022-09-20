package dashboard

import (
	"context"
	"github.com/rancher/rancher/pkg/data/management"
	"github.com/rancher/rancher/pkg/features"
	"github.com/rancher/rancher/pkg/wrangler"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

func EarlyData(ctx context.Context, k8s kubernetes.Interface) error {
	// 创建namespace
	return addCattleGlobalNamespaces(ctx, k8s)
}

func Add(ctx context.Context, wrangler *wrangler.Context, addLocal, removeLocal, embedded bool) error {
	// 1、添加admin 用户信息
	if !features.MCMAgent.Enabled() {
		if _, err := management.BootstrapAdmin(wrangler); err != nil {
			return err
		}
	}
	//2、添加本地集群
	if addLocal {
		if err := addLocalCluster(embedded, wrangler); err != nil {
			return err
		}
		logrus.Infof("")
		logrus.Infof("-----------------------------------------")
		logrus.Infof("添加本地集群成功")
	} else if removeLocal {
		if err := removeLocalCluster(wrangler); err != nil {
			return err
		}
	}
	//3、添加setting 设置
	if err := addSetting(); err != nil {
		return err
	}
	//4、添加charts仓库
	//if err := addRepos(ctx, wrangler); err != nil {
	//	return err
	//}
	//5、添加fleet 角色
	if err := AddFleetRoles(wrangler); err != nil {
		return err
	}
	//6、添加未授权的角色
	return addUnauthenticatedRoles(wrangler.Apply)
}
