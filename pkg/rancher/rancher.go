package rancher

import (
	"context"
	"encoding/json"
	"fmt"
	corev1 "github.com/rancher/rancher/pkg/generated/norman/core/v1"
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg"
	harboruser "github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg/user"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	responsewriter "github.com/rancher/apiserver/pkg/middleware"
	"github.com/rancher/rancher/pkg/api/norman/customization/kontainerdriver"
	"github.com/rancher/rancher/pkg/api/norman/customization/podsecuritypolicytemplate"
	steveapi "github.com/rancher/rancher/pkg/api/steve"
	"github.com/rancher/rancher/pkg/api/steve/aggregation"
	"github.com/rancher/rancher/pkg/api/steve/proxy"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth"
	"github.com/rancher/rancher/pkg/auth/audit"
	"github.com/rancher/rancher/pkg/auth/requests"
	"github.com/rancher/rancher/pkg/controllers/dashboard"
	"github.com/rancher/rancher/pkg/controllers/dashboard/apiservice"
	"github.com/rancher/rancher/pkg/controllers/dashboardapi"
	managementauth "github.com/rancher/rancher/pkg/controllers/management/auth"
	crds "github.com/rancher/rancher/pkg/crds/dashboard"
	dashboarddata "github.com/rancher/rancher/pkg/data/dashboard"
	"github.com/rancher/rancher/pkg/features"
	mgmntv3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	util2 "github.com/rancher/rancher/pkg/k8sproxy/karmadaproxy/util"
	"github.com/rancher/rancher/pkg/multiclustermanager"
	"github.com/rancher/rancher/pkg/namespace"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/tls"
	"github.com/rancher/rancher/pkg/ui"
	"github.com/rancher/rancher/pkg/websocket"
	"github.com/rancher/rancher/pkg/wrangler"
	aggregation2 "github.com/rancher/steve/pkg/aggregation"
	steveauth "github.com/rancher/steve/pkg/auth"
	steveserver "github.com/rancher/steve/pkg/server"
	"github.com/rancher/wrangler/pkg/k8scheck"
	"github.com/rancher/wrangler/pkg/unstructured"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	v1 "k8s.io/api/core/v1"
	k8serror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/net"
	k8dynamic "k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

const (
	encryptionConfigUpdate = "provisioner.cattle.io/encrypt-migrated"

	// karmadaSecretName is the name of the secret on karmada host platform
	karmadaSecretName = "karmada-dashboard-token"

	// karmadaSecretNamespace is the name of the Namespace in which secret resides
	karmadaSecretNamespace = "karmada-system"

	// karmadaServiceAccount is the name of the karmada-dashboard's ServiceAccount
	karmadaServiceAccount = "karmada-dashboard"
)

type Options struct {
	ACMEDomains       cli.StringSlice
	AddLocal          string // AddLocal
	Embedded          bool
	BindHost          string
	HTTPListenPort    int
	HTTPSListenPort   int
	K8sMode           string // k8s mode
	Debug             bool
	Trace             bool
	NoCACerts         bool
	AuditLogPath      string // 日志相关
	AuditLogMaxage    int
	AuditLogMaxsize   int
	AuditLogMaxbackup int
	AuditLevel        int
	Features          string
	ClusterRegistry   string
}

type Rancher struct {
	Auth     steveauth.Middleware //steveauth
	Handler  http.Handler
	Wrangler *wrangler.Context
	Steve    *steveserver.Server

	auditLog   *audit.LogWriter
	authServer *auth.Server
	opts       *Options
}

func New(ctx context.Context, clientConfg clientcmd.ClientConfig, opts *Options) (*Rancher, error) {
	var (
		authServer *auth.Server
	)

	if opts == nil {
		opts = &Options{}
	}

	restConfig, err := clientConfg.ClientConfig()
	if err != nil {
		return nil, err
	}
	// 1、验证 restConfig 是否可用
	restConfig, err = setupAndValidationRESTConfig(ctx, restConfig)
	if err != nil {
		return nil, err
	}

	// Run the encryption migration before any controllers run otherwise the fields will be dropped/
	// 第一次启动的时候并不起作用
	if err := migrateEncryptionConfig(ctx, restConfig); err != nil {
		return nil, err
	}
	// 2、构建wranglerContext，启动websocket server 重点，管理平台核心功能
	wranglerContext, err := wrangler.NewContext(ctx, clientConfg, restConfig)
	if err != nil {
		return nil, err
	}
	//3、页面早期数据获取，获取fleet-local 和cattle-system 的命名空间，如果没有则重新创建，在host集群中
	if err := dashboarddata.EarlyData(ctx, wranglerContext.K8s); err != nil {
		return nil, err
	}
	//4、判断是否为嵌入式，用于docker 启动 构建rancher service 和对应的endpoint 和webhook
	//if opts.Embedded {
	//	if err := setupRancherService(ctx, restConfig, opts.HTTPSListenPort); err != nil {
	//		return nil, err
	//	}
	//	if err := bumpRancherWebhookIfNecessary(ctx, restConfig); err != nil {
	//		return nil, err
	//	}
	//}
	//5、构建MultiClusterManager 重点
	wranglerContext.MultiClusterManager = newMCM(wranglerContext, opts)
	logrus.Infof("crds.CreateFeatureCRD ")
	// Initialize Features as early as possible
	//6、初始化所有的FeatureCRD 和对CRD资源进行补全操作
	if err := crds.CreateFeatureCRD(ctx, restConfig); err != nil {
		return nil, err
	}

	if err := features.MigrateFeatures(wranglerContext.Mgmt.Feature(), wranglerContext.CRD.CustomResourceDefinition(), wranglerContext.Mgmt.Cluster()); err != nil {
		return nil, fmt.Errorf("migrating features: %w", err)
	}
	features.InitializeFeatures(wranglerContext.Mgmt.Feature(), opts.Features)

	// 7、注册podsecuritypolicytemplate，kontainerdriver（容器驱动），managementauth 用于wrangler启动的时候controller直接工作，用于k8s资源的CRUD操作
	podsecuritypolicytemplate.RegisterIndexers(wranglerContext)
	kontainerdriver.RegisterIndexers(wranglerContext)
	managementauth.RegisterWranglerIndexers(wranglerContext)
	//8、构建webhook的crd，绑定CRD和fleet
	if err := crds.Create(ctx, restConfig); err != nil {
		return nil, err
	}
	logrus.Infof("crds.Create finish ")
	if features.MCM.Enabled() && !features.Fleet.Enabled() {
		logrus.Info("fleet can't be turned off when MCM is enabled. Turning on fleet feature")
		if err := features.SetFeature(wranglerContext.Mgmt.Feature(), features.Fleet.Name(), true); err != nil {
			return nil, err
		}
	}
	logrus.Infof("features.Auth.Enabled() :", features.Auth.Enabled())
	// 9、判断是否开启多租户功能
	//if features.Auth.Enabled() {
	authServer, err = auth.NewServer(ctx, restConfig)
	//	if err != nil {
	//		return nil, err
	//	}
	//} else {
	//	authServer, err = auth.NewAlwaysAdmin()
	//	if err != nil {
	//		return nil, err
	//	}
	//}
	//10、构建steve Kubernetes API Translator,这里并没有构建steveserver.router
	steve, err := steveserver.New(ctx, restConfig, &steveserver.Options{
		ServerVersion:   settings.ServerVersion.Get(),
		Controllers:     wranglerContext.Controllers, //一样的
		AccessSetLookup: wranglerContext.ASL,
		AuthMiddleware:  steveauth.ExistingContext,
		Next:            ui.New(wranglerContext.Mgmt.Preference().Cache(), wranglerContext.Mgmt.ClusterRegistrationToken().Cache()),
		ClusterRegistry: opts.ClusterRegistry,
	})
	if err != nil {
		return nil, err
	}
	//11、集群代理，请求下游集群的路由 和handler
	clusterProxy, err := proxy.NewProxyMiddleware(wranglerContext.K8s.AuthorizationV1(),
		wranglerContext.TunnelServer.Dialer, // 代理方法的入口函数
		wranglerContext.Mgmt.Cluster().Cache(),
		localClusterEnabled(opts),
		steve,
	)
	if err != nil {
		return nil, err
	}

	additionalAPIPreMCM := steveapi.AdditionalAPIsPreMCM(wranglerContext)
	additionalAPI, err := steveapi.AdditionalAPIs(ctx, wranglerContext, steve)
	if err != nil {
		return nil, err
	}
	// 12、构建日志相关，NewAuditLogMiddleware通过拦截器的方式记录所有的请求日志,类似java中的aop请求拦截
	auditLogWriter := audit.NewLogWriter(opts.AuditLogPath, opts.AuditLevel, opts.AuditLogMaxage, opts.AuditLogMaxbackup, opts.AuditLogMaxsize)
	auditFilter, err := audit.NewAuditLogMiddleware(auditLogWriter)
	if err != nil {
		return nil, err
	}
	aggregationMiddleware := aggregation.NewMiddleware(ctx, wranglerContext.Mgmt.APIService(), wranglerContext.TunnelServer)
	// 13、构建rancher
	return &Rancher{
		Auth: authServer.Authenticator.Chain(
			auditFilter), // 审计
		Handler: responsewriter.Chain{ // rancher的处理链
			auth.SetXAPICattleAuthHeader,      // 授权检测
			responsewriter.ContentTypeOptions, // 添加请求头 X-Content-Type-Options
			websocket.NewWebsocketHandler,     // 转化为websocker
			proxy.RewriteLocalCluster,         // 重写到本地cluster
			clusterProxy,
			aggregationMiddleware,
			additionalAPIPreMCM,
			wranglerContext.MultiClusterManager.Middleware,
			authServer.Management,
			additionalAPI,
			requests.NewRequireAuthenticatedFilter("/v1/", "/v1/management.cattle.io.setting"), //认证过滤器2
		}.Handler(steve), //Handler 方式是封装的middlewares 用于加载http的middlewares 这里返回的是一个http.Handler，需要注意的是调佣先后
		Wrangler:   wranglerContext,
		Steve:      steve,
		auditLog:   auditLogWriter,
		authServer: authServer,
		opts:       opts,
	}, nil
}

func (r *Rancher) Start(ctx context.Context) error {
	// 1、往Wrangler注册不同的crd资源
	if err := dashboardapi.Register(ctx, r.Wrangler); err != nil {
		return err
	}
	logrus.Infof("dashboardapi.Register ")
	if err := steveapi.Setup(ctx, r.Steve, r.Wrangler); err != nil {
		return err
	}
	// 2、启动Start，之后controller 可以监听不同的资源变化，后面调用DeferredServer，核心方法1
	logrus.Infof("steveapi.Setup ")
	if features.MCM.Enabled() {
		if err := r.Wrangler.MultiClusterManager.Start(ctx); err != nil {
			return err
		}
	}
	logrus.Infof("Wrangler.OnLeader ")
	// 获取领导权，一直执行直到成功返回true  核心方法2
	r.Wrangler.OnLeader(func(ctx context.Context) error {
		//3、添加dashboard 数据，启动数据的添加，主要是用户数据、角色数据、仓库数据
		if err := dashboarddata.Add(ctx, r.Wrangler, localClusterEnabled(r.opts), r.opts.AddLocal == "false", r.opts.Embedded); err != nil {
			return err
		}
		//4、注册dashboard相关的controller 很多controller
		if err := r.Wrangler.StartWithTransaction(ctx, func(ctx context.Context) error { return dashboard.Register(ctx, r.Wrangler, r.opts.Embedded) }); err != nil {
			return err
		}
		// 5、清除之前的所有的用户token
		if err := forceUpgradeLogout(r.Wrangler.Core.ConfigMap(), r.Wrangler.Mgmt.Token(), "v2.6.0"); err != nil {
			return err
		}
		//6、集群级别的初始化操作
		if err := forceSystemAndDefaultProjectCreation(r.Wrangler.Core.ConfigMap(), r.Wrangler.Mgmt.Cluster()); err != nil {
			return err
		}
		//7、 更新controller 的configmap
		if features.MCM.Enabled() {
			if err := forceSystemNamespaceAssignment(r.Wrangler.Core.ConfigMap(), r.Wrangler.Mgmt.Project()); err != nil {
				return err
			}
		}
		//8、确保cattle-system 和 fleet-default 都有秘钥
		return copyCAAdditionalSecret(r.Wrangler.Core.Secret())
	})
	//9、启动authServer
	if err := r.authServer.Start(ctx, false); err != nil {
		return err
	}

	r.Wrangler.OnLeader(r.authServer.OnLeader)
	r.auditLog.Start(ctx)
	// 10、启动Wrangler
	return r.Wrangler.Start(ctx)
}

func (r *Rancher) ListenAndServe(ctx context.Context) error {
	//1、核心服务启动
	logrus.Infof("ListenAndServe ")
	if err := r.Start(ctx); err != nil {
		return err
	}

	r.Wrangler.MultiClusterManager.Wait(ctx)
	logrus.Infof("MultiClusterManager ")
	// 2、监听Secret的变化
	r.startAggregation(ctx)
	go r.Steve.StartAggregation(ctx)
	//3、启动ListenAndServe，把所有的handler 都放到http server 中
	logrus.Infof("StartAggregation ")

	// 首次注册平台
	//go func() {
	//	logrus.Infof("首次注册DCNP")
	//	err := r.dcnpRegister()
	//	if err != nil {
	//		logrus.Error(err.Error())
	//	} else {
	//		logrus.Infof("DCNP注册完成")
	//	}
	//}()

	// 在karmada host平台创建token secret
	go createKarmadaToken(r.Wrangler.K8s)

	// 创建 harbor admin-edgesphere 用户
	go createHarborEdgesphereAdmin()

	if err := tls.ListenAndServe(ctx, r.Wrangler.RESTConfig,
		r.Auth(r.Handler),
		r.opts.BindHost,
		r.opts.HTTPSListenPort,
		r.opts.HTTPListenPort,
		r.opts.ACMEDomains,
		r.opts.NoCACerts); err != nil {
		return err
	}

	<-ctx.Done()
	return ctx.Err()
}

func (r *Rancher) startAggregation(ctx context.Context) {

	aggregation2.Watch(ctx, r.Wrangler.Core.Secret(), namespace.System, "stv-aggregation", r.Handler)
}

func newMCM(wrangler *wrangler.Context, opts *Options) wrangler.MultiClusterManager {
	return multiclustermanager.NewDeferredServer(wrangler, &multiclustermanager.Options{
		RemoveLocalCluster:  opts.AddLocal == "false",
		LocalClusterEnabled: localClusterEnabled(opts),
		Embedded:            opts.Embedded,
		HTTPSListenPort:     opts.HTTPSListenPort,
		Debug:               opts.Debug,
		Trace:               opts.Trace,
	})
}

func setupAndValidationRESTConfig(ctx context.Context, restConfig *rest.Config) (*rest.Config, error) {
	// 1、steveserver
	restConfig = steveserver.RestConfigDefaults(restConfig)
	// 2、每2s请求一个集群的server version 直到返回成功
	return restConfig, k8scheck.Wait(ctx, *restConfig)
}

func localClusterEnabled(opts *Options) bool {
	if opts.AddLocal == "true" || opts.AddLocal == "auto" {
		return true
	}
	return false
}

// setupRancherService will ensure that a Rancher service with a custom endpoint exists that will be used
// to access Rancher
func setupRancherService(ctx context.Context, restConfig *rest.Config, httpsListenPort int) error {
	//1、构建clientset
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("error setting up kubernetes clientset while setting up rancher service: %w", err)
	}

	service := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      apiservice.RancherServiceName,
			Namespace: namespace.System,
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Protocol:   v1.ProtocolTCP,
					Port:       443,
					TargetPort: intstr.FromInt(httpsListenPort + 1),
				},
			},
		},
	}

	refreshService := false

	s, err := clientset.CoreV1().Services(namespace.System).Get(ctx, apiservice.RancherServiceName, metav1.GetOptions{})
	if err != nil {
		if k8serror.IsNotFound(err) {
			refreshService = true
		} else {
			return fmt.Errorf("error looking for rancher service: %w", err)
		}
	} else {
		if s.Spec.String() != service.Spec.String() {
			refreshService = true
		}
	}

	if refreshService {
		logrus.Debugf("setupRancherService refreshing service")
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if s, err := clientset.CoreV1().Services(namespace.System).Get(ctx, apiservice.RancherServiceName, metav1.GetOptions{}); err != nil {
				if k8serror.IsNotFound(err) {
					if _, err := clientset.CoreV1().Services(namespace.System).Create(ctx, &service, metav1.CreateOptions{}); err != nil {
						return err
					}
				} else {
					return err
				}
			} else {
				s.Spec.Ports = service.Spec.Ports
				if _, err := clientset.CoreV1().Services(namespace.System).Update(ctx, s, metav1.UpdateOptions{}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("setupRancherService error refreshing service: %w", err)
		}
	}

	ip, err := net.ChooseHostInterface()
	if err != nil {
		return fmt.Errorf("setupRancherService error getting host IP while setting up rancher service: %w", err)
	}

	endpoint := v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      apiservice.RancherServiceName,
			Namespace: namespace.System,
		},
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []v1.EndpointAddress{
					{
						IP: ip.String(),
					},
				},
				Ports: []v1.EndpointPort{
					{
						Port: int32(httpsListenPort + 1),
					},
				},
			},
		},
	}

	refreshEndpoint := false
	e, err := clientset.CoreV1().Endpoints(namespace.System).Get(ctx, apiservice.RancherServiceName, metav1.GetOptions{})
	if err != nil {
		if k8serror.IsNotFound(err) {
			refreshEndpoint = true
		} else {
			return fmt.Errorf("error looking for rancher endpoint while setting up rancher service: %w", err)
		}
	} else {
		if e.Subsets[0].String() != endpoint.Subsets[0].String() && len(e.Subsets) != 1 {
			logrus.Debugf("setupRancherService subsets did not match, refreshing endpoint (%s vs %s)", e.Subsets[0].String(), endpoint.String())
			refreshEndpoint = true
		}
	}

	if refreshEndpoint {
		logrus.Debugf("setupRancherService refreshing endpoint")
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if e, err := clientset.CoreV1().Endpoints(namespace.System).Get(ctx, apiservice.RancherServiceName, metav1.GetOptions{}); err != nil {
				if k8serror.IsNotFound(err) {
					if _, err := clientset.CoreV1().Endpoints(namespace.System).Create(ctx, &endpoint, metav1.CreateOptions{}); err != nil {
						return err
					}
				} else {
					return err
				}
			} else {
				e.Subsets = endpoint.Subsets
				if _, err := clientset.CoreV1().Endpoints(namespace.System).Update(ctx, e, metav1.UpdateOptions{}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("setupRancherService error refreshing endpoint: %w", err)
		}
	}
	return nil
}

// bumpRancherServiceVersion bumps the version of rancher-webhook if it is detected that the version is less than
// v0.2.2-alpha1. This is because the version of rancher-webhook less than v0.2.2-alpha1 does not support Kubernetes v1.22+
// This should only be called when Rancher is run in a Docker container because the Kubernetes version and Rancher version
// are bumped at the same time. In a Kubernetes cluster, usually the Rancher version is bumped when the cluster is upgraded.
func bumpRancherWebhookIfNecessary(ctx context.Context, restConfig *rest.Config) error {
	webhookVersionParts := strings.Split(os.Getenv("CATTLE_RANCHER_WEBHOOK_MIN_VERSION"), "+up")
	if len(webhookVersionParts) != 2 {
		return nil
	} else if !strings.HasPrefix(webhookVersionParts[1], "v") {
		webhookVersionParts[1] = "v" + webhookVersionParts[1]
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("error setting up kubernetes clientset: %w", err)
	}

	rancherWebhookDeployment, err := clientset.AppsV1().Deployments(namespace.System).Get(ctx, "rancher-webhook", metav1.GetOptions{})
	if err != nil {
		if k8serror.IsNotFound(err) {
			return nil
		}
		return err
	}

	for i, c := range rancherWebhookDeployment.Spec.Template.Spec.Containers {
		imageVersionParts := strings.Split(c.Image, ":")
		if c.Name != "rancher-webhook" || len(imageVersionParts) != 2 {
			continue
		}

		semVer, err := semver.NewVersion(strings.TrimPrefix(imageVersionParts[1], "v"))
		if err != nil {
			continue
		}
		if semVer.LessThan(semver.MustParse("0.2.2-alpha1")) {
			rancherWebhookDeployment = rancherWebhookDeployment.DeepCopy()
			c.Image = fmt.Sprintf("%s:%s", imageVersionParts[0], webhookVersionParts[1])
			rancherWebhookDeployment.Spec.Template.Spec.Containers[i] = c

			_, err = clientset.AppsV1().Deployments(namespace.System).Update(ctx, rancherWebhookDeployment, metav1.UpdateOptions{})
			return err
		}
	}

	return nil
}

// migrateEncryptionConfig uses the dynamic client to get all clusters and then marshals them through the
// standard go JSON package using the updated backing structs in RKE that include JSON tags. The k8s JSON
// tools are strict with casing so the fields would be dropped before getting saved back in the proper casing
// if any controller touches the cluster first. See https://github.com/rancher/rancher/issues/31385
func migrateEncryptionConfig(ctx context.Context, restConfig *rest.Config) error {
	dynamicClient, err := k8dynamic.NewForConfig(restConfig)
	if err != nil {
		return err
	}
	//1、构建集群、资源的clients
	clusterDynamicClient := dynamicClient.Resource(mgmntv3.ClusterGroupVersionResource)
	//2、查询所有的集群
	clusters, err := clusterDynamicClient.List(ctx, metav1.ListOptions{})
	logrus.Infof("clusterDynamicClient clusters ", clusters)
	if err != nil {
		if !k8serror.IsNotFound(err) {
			return err
		}
		// IsNotFound error means the CRD type doesn't exist in the cluster, indicating this is the first Rancher startup
		return nil
	}

	var allErrors error

	for _, c := range clusters.Items {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			rawDynamicCluster, err := clusterDynamicClient.Get(ctx, c.GetName(), metav1.GetOptions{})
			if err != nil {
				return err
			}

			annotations := rawDynamicCluster.GetAnnotations()
			if annotations != nil && annotations[encryptionConfigUpdate] == "true" {
				return nil
			}

			clusterBytes, err := rawDynamicCluster.MarshalJSON()
			if err != nil {
				return errors.Wrap(err, "error trying to Marshal dynamic cluster")
			}

			var cluster *v3.Cluster

			if err := json.Unmarshal(clusterBytes, &cluster); err != nil {
				return errors.Wrap(err, "error trying to Unmarshal dynamicCluster into v3 cluster")
			}

			if cluster.Annotations == nil {
				cluster.Annotations = make(map[string]string)
			}
			cluster.Annotations[encryptionConfigUpdate] = "true"

			u, err := unstructured.ToUnstructured(cluster)
			if err != nil {
				return err
			}

			_, err = clusterDynamicClient.Update(ctx, u, metav1.UpdateOptions{})
			return err
		})
		if err != nil {
			allErrors = multierror.Append(err, allErrors)
		}
	}
	return allErrors
}

func (r *Rancher) dcnpRegister() error {
	// 更新server-url、first-login、telemetry-opt
	err := firstLogin(r.Wrangler)
	if err != nil {
		return err
	}

	err = telemetryOpt(r.Wrangler)
	if err != nil {
		return err
	}

	err = serverUrl(r.Wrangler)
	if err != nil {
		return err
	}

	// 创建eula-agreed
	err = eulaAgreed(r.Wrangler)
	if err != nil {
		return err
	}

	return nil
}

func firstLogin(context *wrangler.Context) error {
	// 获取 first-login
	firstLoginSetting, err := context.Mgmt.Setting().Get("first-login", metav1.GetOptions{})
	if err != nil {
		logrus.Error("无法获取setting：first-login")
		return err
	}

	// 更新 first-login
	if firstLoginSetting.Value == "" {
		firstLoginSetting.Value = "false"
		_, err := context.Mgmt.Setting().Update(firstLoginSetting)
		if err != nil {
			return err
		}
	}
	return nil
}

func telemetryOpt(context *wrangler.Context) error {
	// 获取 telemetry-opt
	telemetryOptSetting, err := context.Mgmt.Setting().Get("telemetry-opt", metav1.GetOptions{})
	if err != nil {
		logrus.Error("无法获取setting：telemetry-opt")
		return err
	}

	// 更新 telemetry-opt
	if telemetryOptSetting.Value == "" {
		telemetryOptSetting.Value = "in"
		_, err := context.Mgmt.Setting().Update(telemetryOptSetting)
		if err != nil {
			return err
		}
	}

	return nil
}

func serverUrl(context *wrangler.Context) error {
	// 获取 server-url
	serverUrlSetting, err := context.Mgmt.Setting().Get("server-url", metav1.GetOptions{})
	if err != nil {
		logrus.Error("无法获取setting：server-url")
		return err
	}

	// 更新 server-url
	if serverUrlSetting.Value == "" {
		serverURL := os.Getenv("ServerURL")
		if serverURL == "" {
			return errors.New("无法找到环境变量：ServerURL")
		}
		serverUrlSetting.Value = "https://" + serverURL

		_, err = context.Mgmt.Setting().Update(serverUrlSetting)
		if err != nil {
			return err
		}
	}
	return nil
}

func eulaAgreed(context *wrangler.Context) error {
	// 获取 eula-agreed
	_, err := context.Mgmt.Setting().Get("eula-agreed", metav1.GetOptions{})
	if err != nil {
		// 创建 eula-agreed
		var eulaAgreedSetting v3.Setting
		eulaAgreedSetting.Name = "eula-agreed"
		eulaAgreedSetting.Kind = "Setting"
		eulaAgreedSetting.APIVersion = "management.cattle.io/v3"
		UTCTime := getUTCTime()
		eulaAgreedSetting.Default = UTCTime
		eulaAgreedSetting.Value = UTCTime

		_, err := context.Mgmt.Setting().Create(&eulaAgreedSetting)
		if err != nil {
			return err
		}
	}
	return nil
}

func getUTCTime() string {
	t := time.Now().UTC().String()
	tList := strings.Split(t, " ")
	t_UTC := tList[0] + "T" + tList[1][:12] + "Z"
	return t_UTC
}

func createKarmadaToken(client kubernetes.Interface) {
	logrus.Infof("createKarmadaToken")
	karmadaConfig, err := util2.GetKarmadaConfig(client)
	if err != nil {
		logrus.Error(err.Error())
		return
	}
	controlPlaneKubeClient := kubernetes.NewForConfigOrDie(karmadaConfig)

	// 判断karmada host平面的secret是否存在
	ok, err := util2.IfSecretExists(client, karmadaSecretNamespace, karmadaSecretName)
	if err != nil {
		logrus.Error(err.Error())
		return
	}
	if ok {
		logrus.Info("karmadaHost secret 已经存在")
		return
	}

	// 获取karmada控制平台上的secret
	serviceAccount, err := controlPlaneKubeClient.CoreV1().ServiceAccounts(karmadaSecretNamespace).Get(context.TODO(), karmadaServiceAccount, metav1.GetOptions{})
	if err != nil {
		logrus.Error(err.Error())
		return
	}
	karmadaControlPlaneSecret, err := util2.GetTargetSecret(controlPlaneKubeClient, serviceAccount.Secrets, v1.SecretTypeServiceAccountToken, karmadaSecretNamespace)
	if err != nil {
		logrus.Error(err.Error())
		return
	}

	// 创建 karmadaHostPlaneSecret
	karmadaHostPlaneSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      karmadaSecretName,
			Namespace: karmadaSecretNamespace,
		},
		Data: map[string][]byte{
			"token": karmadaControlPlaneSecret.Data["token"],
		},
	}
	logrus.Infof("在 karmada Host 平面创建secret")
	_, err = util2.CreateSecret(client, karmadaHostPlaneSecret)
	if err != nil {
		logrus.Error(err.Error())
		return
	}
	logrus.Infof("secret: %v 创建成功", karmadaSecretName)
}

// 创建 harbor admin-edgesphere 用户
func createHarborEdgesphereAdmin() {
	logrus.Info("初始化制品库")
	username := pkg.HarborEdgesphereAdmin
	//password := pkg.HarborAdminPassword
	password := "Harbor12345"
	email := username + "@email.com"

	// 创建 harbor 用户
	if err := harboruser.Create(username, password, email, username); err != nil {
		logrus.Errorf("创建制品库用户%v失败: %v", username, err.Error())
	}

	// 设置为管理员
	if err := harboruser.SetAdmin(username, true); err != nil {
		logrus.Errorf("设置制品库管理员%v失败: %v", username, err.Error())
		return
	}
	logrus.Info("初始化制品库成功")
}
