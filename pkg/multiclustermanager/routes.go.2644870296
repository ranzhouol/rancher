package multiclustermanager

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rancher/apiserver/pkg/parse"
	"github.com/rancher/apiserver/pkg/urlbuilder"
	"github.com/rancher/rancher/pkg/api/norman"
	"github.com/rancher/rancher/pkg/api/norman/customization/aks"
	"github.com/rancher/rancher/pkg/api/norman/customization/clusterregistrationtokens"
	"github.com/rancher/rancher/pkg/api/norman/customization/gke"
	"github.com/rancher/rancher/pkg/api/norman/customization/oci"
	"github.com/rancher/rancher/pkg/api/norman/customization/vsphere"
	managementapi "github.com/rancher/rancher/pkg/api/norman/server"
	"github.com/rancher/rancher/pkg/auth/providers/publicapi"
	"github.com/rancher/rancher/pkg/auth/providers/saml"
	"github.com/rancher/rancher/pkg/auth/requests"
	"github.com/rancher/rancher/pkg/auth/requests/sar"
	"github.com/rancher/rancher/pkg/auth/tokens"
	"github.com/rancher/rancher/pkg/auth/webhook"
	"github.com/rancher/rancher/pkg/channelserver"
	"github.com/rancher/rancher/pkg/clustermanager"
	rancherdialer "github.com/rancher/rancher/pkg/dialer"
	"github.com/rancher/rancher/pkg/httpproxy"
	k8sProxyPkg "github.com/rancher/rancher/pkg/k8sproxy"
	"github.com/rancher/rancher/pkg/karmadaproxy"
	"github.com/rancher/rancher/pkg/karmadaproxy/join"
	"github.com/rancher/rancher/pkg/metrics"
	"github.com/rancher/rancher/pkg/multiclustermanager/whitelist"
	"github.com/rancher/rancher/pkg/pipeline/hooks"
	"github.com/rancher/rancher/pkg/rbac"
	"github.com/rancher/rancher/pkg/rkenodeconfigserver"
	"github.com/rancher/rancher/pkg/telemetry"
	"github.com/rancher/rancher/pkg/tunnelserver/mcmauthorizer"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/steve/pkg/auth"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/proxy"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"strings"
)

var (
	er             = &errorResponder{}
	managerContext *config.ScaledContext
)

type errorResponder struct {
}

func (e *errorResponder) Error(w http.ResponseWriter, req *http.Request, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(err.Error()))
}

func router(ctx context.Context, localClusterEnabled bool, tunnelAuthorizer *mcmauthorizer.Authorizer, scaledContext *config.ScaledContext, clusterManager *clustermanager.Manager) (func(http.Handler) http.Handler, error) {

	var (
		k8sProxy             = k8sProxyPkg.New(scaledContext, scaledContext.Dialer, clusterManager)
		connectHandler       = scaledContext.Dialer.(*rancherdialer.Factory).TunnelServer
		connectConfigHandler = rkenodeconfigserver.Handler(tunnelAuthorizer, scaledContext)
		clusterImport        = clusterregistrationtokens.ClusterImport{Clusters: scaledContext.Management.Clusters("")}
		karmadaProxy         = karmadaproxy.NewProxy()
	)
	managerContext = scaledContext
	tokenAPI, err := tokens.NewAPIHandler(ctx, scaledContext, norman.ConfigureAPIUI)
	if err != nil {
		return nil, err
	}

	publicAPI, err := publicapi.NewHandler(ctx, scaledContext, norman.ConfigureAPIUI)
	if err != nil {
		return nil, err
	}

	managementAPI, err := managementapi.New(ctx, scaledContext, clusterManager, k8sProxy, localClusterEnabled)
	if err != nil {
		return nil, err
	}

	metaProxy, err := httpproxy.NewProxy("/proxy/", whitelist.Proxy.Get, scaledContext)
	if err != nil {
		return nil, err
	}

	metricsHandler := metrics.NewMetricsHandler(scaledContext, clusterManager, promhttp.Handler())

	channelserver := channelserver.NewHandler(ctx)

	// Unauthenticated routes
	unauthed := mux.NewRouter()
	unauthed.UseEncodedPath()
	unauthed.Use(urlbuilder.RedirectRewrite)

	matchV1Karmada := func(r *http.Request, match *mux.RouteMatch) bool {
		if strings.HasPrefix(r.URL.Path, "/cluster.karmada.io") || strings.HasPrefix(r.URL.Path, "/policy.karmada.io") {
			logrus.Infof(" multiclustermanager  matchV1Karmada  URL %s ", r.URL.Path)
			match.Vars = map[string]string{"name": "v1/karmada"}
			return true
		}
		return false
	}

	unauthed.Path("/").MatcherFunc(parse.MatchNotBrowser).Handler(managementAPI)
	unauthed.Handle("/v3/connect/config", connectConfigHandler)
	unauthed.Handle("/v3/connect", connectHandler)
	unauthed.Handle("/v3/connect/register", connectHandler)
	unauthed.Handle("/v3/import/{token}_{clusterId}.yaml", http.HandlerFunc(clusterImport.ClusterImportHandler))
	unauthed.Handle("/v3/settings/cacerts", managementAPI).MatcherFunc(onlyGet)
	unauthed.Handle("/v3/settings/first-login", managementAPI).MatcherFunc(onlyGet)
	unauthed.Handle("/v3/settings/ui-banners", managementAPI).MatcherFunc(onlyGet)
	unauthed.Handle("/v3/settings/ui-issues", managementAPI).MatcherFunc(onlyGet)
	unauthed.Handle("/v3/settings/ui-pl", managementAPI).MatcherFunc(onlyGet)
	unauthed.Handle("/v3/settings/ui-brand", managementAPI).MatcherFunc(onlyGet)
	unauthed.Handle("/v3/settings/ui-default-landing", managementAPI).MatcherFunc(onlyGet)
	unauthed.PathPrefix("/hooks").Handler(hooks.New(scaledContext))
	unauthed.PathPrefix("/v1-{prefix}-release/channel").Handler(channelserver)
	unauthed.PathPrefix("/v1-{prefix}-release/release").Handler(channelserver)
	unauthed.PathPrefix("/v1-saml").Handler(saml.AuthHandler())
	unauthed.PathPrefix("/v3-public").Handler(publicAPI)
	// karmada routes
	unauthed.HandleFunc("/karmada/cluster/joinCluster/upLoadConfig", joinClusterConfig).Methods("POST")
	unauthed.MatcherFunc(matchV1Karmada).HandlerFunc(karmadaproxy.ProxyRequestHandler(karmadaProxy))

	// Authenticated routes
	authed := mux.NewRouter()
	authed.UseEncodedPath()
	authed.Use(mux.MiddlewareFunc(auth.ToMiddleware(requests.NewImpersonatingAuth(sar.NewSubjectAccessReview(clusterManager)))))
	authed.Use(mux.MiddlewareFunc(rbac.NewAccessControlHandler()))
	authed.Use(requests.NewAuthenticatedFilter)

	authed.Path("/meta/{resource:aks.+}").Handler(aks.NewAKSHandler(scaledContext))
	authed.Path("/meta/{resource:gke.+}").Handler(gke.NewGKEHandler(scaledContext))
	authed.Path("/meta/oci/{resource}").Handler(oci.NewOCIHandler(scaledContext))
	authed.Path("/meta/vsphere/{field}").Handler(vsphere.NewVsphereHandler(scaledContext))
	authed.Path("/v3/tokenreview").Methods(http.MethodPost).Handler(&webhook.TokenReviewer{})
	authed.Path("/metrics").Handler(metricsHandler)
	authed.Path("/metrics/{clusterID}").Handler(metricsHandler)
	authed.PathPrefix("/k8s/clusters/").Handler(k8sProxy)
	authed.PathPrefix("/meta/proxy").Handler(metaProxy)
	authed.PathPrefix("/v1-telemetry").Handler(telemetry.NewProxy())
	authed.PathPrefix("/v3/identit").Handler(tokenAPI)
	authed.PathPrefix("/v3/token").Handler(tokenAPI)
	authed.PathPrefix("/v3").Handler(managementAPI)

	unauthed.NotFoundHandler = authed
	return func(next http.Handler) http.Handler {
		authed.NotFoundHandler = next
		return unauthed
	}, nil
}

// onlyGet will match only GET but will not return a 405 like route.Methods and instead just not match
func onlyGet(req *http.Request, m *mux.RouteMatch) bool {
	return req.Method == http.MethodGet
}

func karmadaHandle(rw http.ResponseWriter, req *http.Request) {
	logrus.Infof(" multiclustermanager URL.Path %s ", req.URL)
	logrus.Infof(" multiclustermanager req.Header%s ", req.Header.Get("Authorization"))
	httpProxy := proxy.NewUpgradeAwareHandler(req.URL, nil, true, false, er)
	httpProxy.ServeHTTP(rw, req)
}

/// join cluster config
func joinClusterConfig(writer http.ResponseWriter, request *http.Request) {
	//join cluster name and config
	clusterName := request.FormValue("clusterName")
	clusterConfig, header, _ := request.FormFile("clusterConfig")

	byteClusterConfig, _ := ioutil.ReadAll(clusterConfig)
	logrus.Infof("ClusterName=%s\n", clusterName)
	logrus.Infof("upload filename:", header.Filename)

	//替换集群名字
	strClusterConfig := string(byteClusterConfig)
	indexCurcontext := strings.Index(strClusterConfig, "current-context:")
	if indexCurcontext != -1 {
		indexCurcontextStart := indexCurcontext + 17
		indexCurcontextEnd := indexCurcontextStart
		for ; indexCurcontextEnd < len(strClusterConfig); indexCurcontextEnd++ {
			if string(strClusterConfig[indexCurcontextEnd]) == "\n" {
				break
			}
		}
		replace_name := strClusterConfig[indexCurcontextStart:indexCurcontextEnd]
		strClusterConfig = strings.Replace(strClusterConfig, replace_name, clusterName, -1)
	}
	byteClusterConfig = []byte(strClusterConfig)

	//get join cluster RestConfig
	clusterRestConfig, err := clientcmd.RESTConfigFromKubeConfig(byteClusterConfig)
	if err != nil {
		//panic(err)
		fmt.Errorf("err: ", err.Error())
		return
	}

	//get secret
	karmadaSecret, err := managerContext.Core.Secrets("karmada-system").Get("karmada-kubeconfig", metav1.GetOptions{})
	//karmadaSecret, err := secretClient.Get(context.TODO(), "karmada-kubeconfig", metav1.GetOptions{})
	if err != nil {
		karmadaSecret, err = managerContext.Core.Secrets("karmada-system").Get("kubeconfig", metav1.GetOptions{})
		if err != nil {
			fmt.Errorf("err: ", err.Error())
			return
		}
	}
	//get karmadarestconfig
	karmadaConfig, err := clientcmd.RESTConfigFromKubeConfig(karmadaSecret.Data["kubeconfig"])
	if err != nil {
		fmt.Errorf("err: ", err.Error())
		return
	}

	//join cluster
	join.JoinCluster(karmadaConfig, clusterRestConfig, "",clusterName)
	//对参数进行修改，之后进行
}
