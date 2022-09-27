package multiclustermanager

import (
	"context"
	"fmt"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/rancher/norman/types"
	"github.com/rancher/rancher/pkg/auth/providerrefresh"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	"github.com/rancher/rancher/pkg/auth/tokens"
	"github.com/rancher/rancher/pkg/catalog/manager"
	"github.com/rancher/rancher/pkg/clustermanager"
	managementController "github.com/rancher/rancher/pkg/controllers/management"
	"github.com/rancher/rancher/pkg/controllers/management/clusterupstreamrefresher"
	managementcrds "github.com/rancher/rancher/pkg/crds/management"
	managementdata "github.com/rancher/rancher/pkg/data/management"
	"github.com/rancher/rancher/pkg/dialer"
	"github.com/rancher/rancher/pkg/metrics"
	"github.com/rancher/rancher/pkg/namespace"
	"github.com/rancher/rancher/pkg/systemtokens"
	"github.com/rancher/rancher/pkg/telemetry"
	"github.com/rancher/rancher/pkg/tunnelserver/mcmauthorizer"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/rancher/pkg/wrangler"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Options struct {
	LocalClusterEnabled bool
	RemoveLocalCluster  bool
	Embedded            bool
	HTTPSListenPort     int
	Debug               bool
	Trace               bool
}

type mcm struct {
	ScaledContext       *config.ScaledContext
	clusterManager      *clustermanager.Manager
	router              func(http.Handler) http.Handler
	wranglerContext     *wrangler.Context
	localClusterEnabled bool
	removeLocalCluster  bool
	embedded            bool
	httpsListenPort     int

	startedChan chan struct{}
	startLock   sync.Mutex
}

func buildScaledContext(ctx context.Context, wranglerContext *wrangler.Context, cfg *Options) (*config.ScaledContext,
	*clustermanager.Manager, *mcmauthorizer.Authorizer, error) {
	//1、构建scaledContext
	scaledContext, err := config.NewScaledContext(*wranglerContext.RESTConfig, &config.ScaleContextOptions{
		ControllerFactory: wranglerContext.ControllerFactory,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	scaledContext.Wrangler = wranglerContext
	//2、构建CatalogManager
	scaledContext.CatalogManager = manager.New(scaledContext.Management, scaledContext.Project, scaledContext.Core)
	//3、创建CRD资源
	if err := managementcrds.Create(ctx, wranglerContext.RESTConfig); err != nil {
		return nil, nil, nil, err
	}
	// 4、创建dialerFactory 工厂
	dialerFactory, err := dialer.NewFactory(scaledContext, wranglerContext)
	if err != nil {
		return nil, nil, nil, err
	}
	scaledContext.Dialer = dialerFactory
	//5、创建用户管理器
	userManager, err := common.NewUserManager(scaledContext)
	if err != nil {
		return nil, nil, nil, err
	}

	scaledContext.UserManager = userManager
	scaledContext.RunContext = ctx
	//6、创建系统token
	systemTokens := systemtokens.NewSystemTokensFromScale(scaledContext)
	scaledContext.SystemTokens = systemTokens
	//7、创建集群管理器，用于启动所有的controller
	manager := clustermanager.NewManager(cfg.HTTPSListenPort, scaledContext, wranglerContext.ASL)

	scaledContext.AccessControl = manager
	scaledContext.ClientGetter = manager
	//8、自定义授权控制器
	authorizer := mcmauthorizer.NewAuthorizer(scaledContext)
	wranglerContext.TunnelAuthorizer.Add(authorizer.AuthorizeTunnel)
	scaledContext.PeerManager = wranglerContext.PeerManager

	return scaledContext, manager, authorizer, nil
}

func newMCM(ctx context.Context, wranglerContext *wrangler.Context, cfg *Options) (*mcm, error) {
	//1、构建scaledContext、clusterManager、tunnelAuthorizer
	scaledContext, clusterManager, tunnelAuthorizer, err := buildScaledContext(ctx, wranglerContext, cfg)
	if err != nil {
		return nil, err
	}
	//2、初始化router
	router, err := router(ctx, cfg.LocalClusterEnabled, tunnelAuthorizer, scaledContext, clusterManager)
	if err != nil {
		return nil, err
	}
	//karmada 整合
	karmadaSecret, err := scaledContext.Core.Secrets("karmada-system").Get("karmada-kubeconfig", metav1.GetOptions{})
	logrus.Infof("Rancher karmadaSecret %s", karmadaSecret.Data["kubeconfig"])
	logrus.Infof("Rancher karmadaSecret %s", karmadaSecret.Data["kubeconfig"])

	config, err := clientcmd.RESTConfigFromKubeConfig(karmadaSecret.Data["kubeconfig"])

	//client, err := proxy.NewClientGetterFromConfig(*config)

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	deploymentsClient := clientset.AppsV1().Deployments(apiv1.NamespaceDefault)
	list, err := deploymentsClient.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	for _, d := range list.Items {
		fmt.Printf(" * %s (%d replicas)\n", d.Name, *d.Spec.Replicas)
	}

	if os.Getenv("CATTLE_PROMETHEUS_METRICS") == "true" {
		metrics.Register(ctx, scaledContext)
	}

	mcm := &mcm{
		router:              router,
		ScaledContext:       scaledContext,
		clusterManager:      clusterManager,
		wranglerContext:     wranglerContext,
		localClusterEnabled: cfg.LocalClusterEnabled,
		removeLocalCluster:  cfg.RemoveLocalCluster,
		embedded:            cfg.Embedded,
		httpsListenPort:     cfg.HTTPSListenPort,
		startedChan:         make(chan struct{}),
	}

	go func() {
		<-ctx.Done()
		mcm.started(ctx)
	}()

	return mcm, nil
}

func (m *mcm) started(ctx context.Context) {
	m.startLock.Lock()
	defer m.startLock.Unlock()
	select {
	case <-m.startedChan:
	default:
		close(m.startedChan)
	}
}

func (m *mcm) Wait(ctx context.Context) {
	select {
	case <-m.startedChan:
		for {
			if _, err := m.wranglerContext.Core.Namespace().Get(namespace.GlobalNamespace, metav1.GetOptions{}); err == nil {
				return
			}
			logrus.Infof("Waiting for initial data to be populated")
			time.Sleep(2 * time.Second)
		}
	case <-ctx.Done():
	}
}

func (m *mcm) NormanSchemas() *types.Schemas {
	<-m.startedChan
	return m.ScaledContext.Schemas
}

func (m *mcm) Middleware(next http.Handler) http.Handler {
	return m.router(next)
}

func (m *mcm) Start(ctx context.Context) error {
	var (
		management *config.ManagementContext
	)

	//if dm := os.Getenv("CATTLE_DEV_MODE"); dm == "" {
	//	if err := jailer.CreateJail("driver-jail"); err != nil {
	//		return err
	//	}
	//
	//	if err := cron.StartJailSyncCron(m.ScaledContext); err != nil {
	//		return err
	//	}
	//}
	//1、每隔5s执行依次下面的func 知道成功
	m.wranglerContext.OnLeader(func(ctx context.Context) error {
		err := m.wranglerContext.StartWithTransaction(ctx, func(ctx context.Context) error {
			var (
				err error
			)

			management, err = m.ScaledContext.NewManagementContext()
			if err != nil {
				return errors.Wrap(err, "failed to create management context")
			}
			//2、添加管理数据
			if err := managementdata.Add(ctx, m.wranglerContext, management); err != nil {
				return errors.Wrap(err, "failed to add management data")
			}
			//3、注册资源的controller的handler事件，注册managementController.RegisterWrangler
			managementController.Register(ctx, management, m.ScaledContext.ClientGetter.(*clustermanager.Manager), m.wranglerContext)
			if err := managementController.RegisterWrangler(ctx, m.wranglerContext, management, m.ScaledContext.ClientGetter.(*clustermanager.Manager)); err != nil {
				return errors.Wrap(err, "failed to register wrangler controllers")
			}
			return nil
		})
		if err != nil {
			return err
		}
		//4、启动遥测
		if err := telemetry.Start(ctx, m.httpsListenPort, m.ScaledContext); err != nil {
			return errors.Wrap(err, "failed to telemetry")
		}
		//5、tokens 的过期清理
		tokens.StartPurgeDaemon(ctx, management)
		providerrefresh.StartRefreshDaemon(ctx, m.ScaledContext, management)
		managementdata.CleanupOrphanedSystemUsers(ctx, management)
		clusterupstreamrefresher.MigrateEksRefreshCronSetting(m.wranglerContext)
		go managementdata.CleanupDuplicateBindings(m.ScaledContext, m.wranglerContext)
		go managementdata.CleanupOrphanBindings(m.ScaledContext, m.wranglerContext)
		logrus.Infof("Rancher startup complete")
		return nil
	})

	return nil
}
