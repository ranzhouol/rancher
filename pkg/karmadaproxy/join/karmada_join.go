package join

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/rancher/rancher/pkg/karmadaproxy/util"
	"github.com/rancher/rancher/pkg/karmadaproxy/util/names"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	// SecretTokenKey is the name of secret token key.
	SecretTokenKey = "token"
	// SecretCADataKey is the name of secret caBundle key.
	SecretCADataKey = "caBundle"
)

var (
	// Policy rules allowing full access to resources in the cluster or namespace.
	namespacedPolicyRules = []rbacv1.PolicyRule{
		{
			Verbs:     []string{rbacv1.VerbAll},
			APIGroups: []string{rbacv1.APIGroupAll},
			Resources: []string{rbacv1.ResourceAll},
		},
	}
	clusterPolicyRules = []rbacv1.PolicyRule{
		namespacedPolicyRules[0],
		{
			NonResourceURLs: []string{rbacv1.NonResourceAll},
			Verbs:           []string{"get"},
		},
	}
	karmadaHost    = "https://192.168.49.200:32443/apis"
	managerContext *config.ScaledContext
)

func NewKarmadaJoinProxy(context *config.ScaledContext) *httputil.ReverseProxy {

	url, err := url.Parse(karmadaHost)
	managerContext = context
	if err != nil {
		return nil
	}
	proxy := httputil.NewSingleHostReverseProxy(url)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		modifyRequest(req)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	proxy.Transport = tr
	proxy.ErrorHandler = errorHandler()
	return proxy
}

func modifyRequest(request *http.Request) {
	request.Header.Set("Access-Control-Allow-Origin", "*")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, OPTIONS")

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
	err = JoinCluster(karmadaConfig, clusterRestConfig, "", clusterName)
	if err != nil {
		fmt.Errorf("err: ", err.Error())
		return
	}

	// 重新构建request的body

	request.Body = ioutil.NopCloser(bytes.NewBuffer(jsonStr))
	logrus.Infof(" r.body   %s ", request.Body)

}

func errorHandler() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		fmt.Printf("Got error while modifying response: %v \n", err)
		return
	}
}

func ProxyRequestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, request *http.Request) {
		proxy.ServeHTTP(w, request)
	}
}

// JoinCluster join the cluster into karmada.
func JoinCluster(controlPlaneRestConfig, clusterConfig *rest.Config, clusterNamespace, clusterName string) (err error) {
	// 创建client,用于访问host集群
	controlPlaneKubeClient := kubeclient.NewForConfigOrDie(controlPlaneRestConfig)
	// 创建kubeclient 用于访问 member cluster集群
	clusterKubeClient := kubeclient.NewForConfigOrDie(clusterConfig)

	logrus.Infof("joining cluster config. endpoint: %s", clusterConfig.Host)

	// ensure namespace where the cluster object be stored exists in control plane.
	// 查看namespace
	if _, err = util.EnsureNamespaceExist(controlPlaneKubeClient, clusterNamespace, false); err != nil {
		return err
	}

	clusterSecret, impersonatorSecret, err := obtainCredentialsFromMemberCluster(
		clusterKubeClient, clusterNamespace, clusterName, false)
	if err != nil {
		return err
	}

	// 注册集群到ControllerPlane
	err = registerClusterInControllerPlane(clusterNamespace, clusterName,
		controlPlaneRestConfig, clusterConfig, controlPlaneKubeClient, clusterSecret, impersonatorSecret)
	if err != nil {
		return err
	}

	fmt.Printf("cluster(%s) is joined successfully\n", clusterName)
	return nil
}

func registerClusterInControllerPlane(clusterNamespace, clusterName string, controlPlaneRestConfig, clusterConfig *rest.Config,
	controlPlaneKubeClient kubeclient.Interface, clusterSecret, clusterImpersonatorSecret *corev1.Secret) error {
	// create secret in control plane
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: clusterNamespace,
			Name:      clusterName,
		},
		Data: map[string][]byte{
			SecretCADataKey: clusterSecret.Data["ca.crt"],
			SecretTokenKey:  clusterSecret.Data[SecretTokenKey],
		},
	}
	// 1、创建secret，在host集群中创建对应的secret
	secret, err := util.CreateSecret(controlPlaneKubeClient, secret)
	if err != nil {
		return fmt.Errorf("failed to create secret in control plane. error: %v", err)
	}

	// create secret to store impersonation info in control plane
	impersonatorSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: clusterNamespace,
			Name:      names.GenerateImpersonationSecretName(clusterName),
		},
		Data: map[string][]byte{
			SecretTokenKey: clusterImpersonatorSecret.Data[SecretTokenKey],
		},
	}
	//2、创建impersonatorSecret在 host集群中
	impersonatorSecret, err = util.CreateSecret(controlPlaneKubeClient, impersonatorSecret)
	if err != nil {
		return fmt.Errorf("failed to create impersonator secret in control plane. error: %v", err)
	}
	// 创建集群
	//cluster, err := generateClusterInControllerPlane(controlPlaneRestConfig, clusterConfig, clusterName, *secret, *impersonatorSecret)
	//if err != nil {
	//	return err
	//}
	return nil
}

//  从成员集群获取凭证
func obtainCredentialsFromMemberCluster(clusterKubeClient kubeclient.Interface, clusterNamespace, clusterName string, dryRun bool) (*corev1.Secret, *corev1.Secret, error) {
	var err error

	// ensure namespace where the karmada control plane credential be stored exists in cluster.
	if _, err = util.EnsureNamespaceExist(clusterKubeClient, clusterNamespace, dryRun); err != nil {
		return nil, nil, err
	}

	// create a ServiceAccount in cluster.
	serviceAccountObj := &corev1.ServiceAccount{}
	serviceAccountObj.Namespace = clusterNamespace
	serviceAccountObj.Name = names.GenerateServiceAccountName(clusterName)
	if serviceAccountObj, err = util.EnsureServiceAccountExist(clusterKubeClient, serviceAccountObj, dryRun); err != nil {
		return nil, nil, err
	}

	// create a ServiceAccount for impersonation in cluster.
	impersonationSA := &corev1.ServiceAccount{}
	impersonationSA.Namespace = clusterNamespace
	impersonationSA.Name = names.GenerateServiceAccountName("impersonator")
	if impersonationSA, err = util.EnsureServiceAccountExist(clusterKubeClient, impersonationSA, dryRun); err != nil {
		return nil, nil, err
	}

	// create a ClusterRole in cluster.
	clusterRole := &rbacv1.ClusterRole{}
	clusterRole.Name = names.GenerateRoleName(serviceAccountObj.Name)
	clusterRole.Rules = clusterPolicyRules
	if _, err = ensureClusterRoleExist(clusterKubeClient, clusterRole, dryRun); err != nil {
		return nil, nil, err
	}

	// create a ClusterRoleBinding in cluster.
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
	clusterRoleBinding.Name = clusterRole.Name
	clusterRoleBinding.Subjects = buildRoleBindingSubjects(serviceAccountObj.Name, serviceAccountObj.Namespace)
	clusterRoleBinding.RoleRef = buildClusterRoleReference(clusterRole.Name)
	if _, err = ensureClusterRoleBindingExist(clusterKubeClient, clusterRoleBinding, dryRun); err != nil {
		return nil, nil, err
	}

	if dryRun {
		return nil, nil, nil
	}
	// 使用k8s封装的重试机制进行尝试获取
	clusterSecret, err := util.WaitForServiceAccountSecretCreation(clusterKubeClient, serviceAccountObj)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get serviceAccount secret from cluster(%s), error: %v", clusterName, err)
	}

	impersonatorSecret, err := util.WaitForServiceAccountSecretCreation(clusterKubeClient, impersonationSA)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get serviceAccount secret for impersonation from cluster(%s), error: %v", clusterName, err)
	}

	return clusterSecret, impersonatorSecret, nil
}

// ensureClusterRoleExist makes sure that the specific cluster role exist in cluster.
// If cluster role not exit, just create it.
func ensureClusterRoleExist(client kubeclient.Interface, clusterRole *rbacv1.ClusterRole, dryRun bool) (*rbacv1.ClusterRole, error) {
	if dryRun {
		return clusterRole, nil
	}

	exist, err := util.IsClusterRoleExist(client, clusterRole.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check if ClusterRole exist. ClusterRole: %s, error: %v", clusterRole.Name, err)
	}
	if exist {
		logrus.Infof("ensure ClusterRole succeed as already exist. ClusterRole: %s", clusterRole.Name)
		return clusterRole, nil
	}

	createdObj, err := util.CreateClusterRole(client, clusterRole)
	if err != nil {
		return nil, fmt.Errorf("ensure ClusterRole failed due to create failed. ClusterRole: %s, error: %v", clusterRole.Name, err)
	}

	return createdObj, nil
}

// ensureClusterRoleBindingExist makes sure that the specific ClusterRoleBinding exist in cluster.
// If ClusterRoleBinding not exit, just create it.
func ensureClusterRoleBindingExist(client kubeclient.Interface, clusterRoleBinding *rbacv1.ClusterRoleBinding, dryRun bool) (*rbacv1.ClusterRoleBinding, error) {
	if dryRun {
		return clusterRoleBinding, nil
	}

	exist, err := util.IsClusterRoleBindingExist(client, clusterRoleBinding.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check if ClusterRole exist. ClusterRole: %s, error: %v", clusterRoleBinding.Name, err)
	}
	if exist {
		logrus.Infof("ensure ClusterRole succeed as already exist. ClusterRole: %s", clusterRoleBinding.Name)
		return clusterRoleBinding, nil
	}

	createdObj, err := util.CreateClusterRoleBinding(client, clusterRoleBinding)
	if err != nil {
		return nil, fmt.Errorf("ensure ClusterRole failed due to create failed. ClusterRole: %s, error: %v", clusterRoleBinding.Name, err)
	}

	return createdObj, nil
}

// buildRoleBindingSubjects will generate a subject as per service account.
// The subject used by RoleBinding or ClusterRoleBinding.
func buildRoleBindingSubjects(serviceAccountName, serviceAccountNamespace string) []rbacv1.Subject {
	return []rbacv1.Subject{
		{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      serviceAccountName,
			Namespace: serviceAccountNamespace,
		},
	}
}

// buildClusterRoleReference will generate a ClusterRole reference.
func buildClusterRoleReference(roleName string) rbacv1.RoleRef {
	return rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "ClusterRole",
		Name:     roleName,
	}
}
