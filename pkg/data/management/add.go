package management

import (
	"context"

	"github.com/rancher/rancher/pkg/auth/data"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/rancher/pkg/wrangler"
)

func Add(ctx context.Context, wrangler *wrangler.Context, management *config.ManagementContext) error {
	//1、清楚node的sshkey
	if err := sshKeyCleanup(management); err != nil {
		return err
	}
	//2、添加默认的角色信息
	_, err := addRoles(wrangler, management)
	if err != nil {
		return err
	}
	// 添加全局角色
	if err := addClusterRoleForNamespacedCRDs(management); err != nil {
		return err
	}

	if err := data.AuthConfigs(management); err != nil {
		return err
	}
	//TODO 同步chart 仓库数据
	//if err := syncCatalogs(management); err != nil {
	//	return err
	//}

	//if err := addDefaultPodSecurityPolicyTemplates(management); err != nil {
	//	return err
	//}
	//
	//if err := addKontainerDrivers(management); err != nil {
	//	return err
	//}

	if err := addCattleGlobalNamespaces(management); err != nil {
		return err
	}
	//addMachineDrivers(management)
	return nil
}
