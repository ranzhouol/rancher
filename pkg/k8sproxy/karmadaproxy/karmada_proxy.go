package karmadaproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	util2 "github.com/rancher/rancher/pkg/k8sproxy/karmadaproxy/util"
	names2 "github.com/rancher/rancher/pkg/k8sproxy/karmadaproxy/util/names"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clientcertutil "k8s.io/client-go/util/cert"
	bootstrapapi "k8s.io/cluster-bootstrap/token/api"
	bootstraputil "k8s.io/cluster-bootstrap/token/util"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pubkeypin"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const (
	// SecretTokenKey is the name of secret token key.
	SecretTokenKey = "token"

	// SecretCADataKey is the name of secret caBundle key.
	SecretCADataKey = "caBundle"

	// KarmadaConfigPath is the path to karmada-apiserver.config
	KarmadaConfigPath = "/etc/karmada/karmada-apiserver.config"

	// When a token is matched with 'BootstrapTokenPattern', the size of validated substrings returned by
	// regexp functions which contains 'Submatch' in their names will be 3.
	// Submatch 0 is the match of the entire expression, submatch 1 is
	// the match of the first parenthesized subexpression, and so on.
	// e.g.:
	// result := bootstraputil.BootstrapTokenRegexp.FindStringSubmatch("abcdef.1234567890123456")
	// result == []string{"abcdef.1234567890123456","abcdef","1234567890123456"}
	// len(result) == 3
	validatedSubstringsSize = 3
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
	karmadaHost = "https://karmada-apiserver.karmada-system.svc.cluster.local:5443"
	//karmadaHost    = "https://192.168.49.200:32443/apis"
	managerContext *config.ScaledContext
)

func NewKarmadaJoinProxy(context *config.ScaledContext) *httputil.ReverseProxy {
	managerContext = context
	karmadaUrl, err := url.Parse(karmadaHost)
	if err != nil {
		return nil
	}
	proxy := httputil.NewSingleHostReverseProxy(karmadaUrl)

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

func modifyRequest(req *http.Request) {
	req.Header.Set("Access-Control-Allow-Origin", "*")
	req.Header.Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, OPTIONS")
	//判断是否是join
	logrus.Infof("req.RequestURI =%s\n", req.RequestURI)
	logrus.Infof("req.Method =%s\n", req.Method)

	// Push
	if req.Method == "POST" && strings.Contains(req.RequestURI, "/cluster.karmada.io/v1alpha1/clusters") {
		err := NewKarmadaPushJoin(req)
		if err != nil {
			logrus.Errorf("err: %s", err.Error())
		}
	}
}

// NewKarmadaPushJoin : Register cluster with 'Push' mode
func NewKarmadaPushJoin(req *http.Request) error {
	logrus.Infof("Register cluster with 'Push' mode")
	clusterName := req.FormValue("clusterName")
	strClusterConfig := req.FormValue("clusterConfig")
	logrus.Infof("ClusterName=%s\n", clusterName)
	logrus.Infof("clusterConfig=\n%s", strClusterConfig)

	//替换集群名字
	indexCurcontext := strings.Index(strClusterConfig, "current-context:")
	if indexCurcontext != -1 {
		indexCurcontextStart := indexCurcontext + 17
		indexCurcontextEnd := indexCurcontextStart
		for ; indexCurcontextEnd < len(strClusterConfig); indexCurcontextEnd++ {
			if string(strClusterConfig[indexCurcontextEnd]) == "\n" {
				break
			}
		}
		replaceName := strClusterConfig[indexCurcontextStart:indexCurcontextEnd]
		strClusterConfig = strings.Replace(strClusterConfig, replaceName, clusterName, -1)
	}

	byteClusterConfig := []byte(strClusterConfig)

	//
	serverIndex := strings.Index(strClusterConfig, "server: ")
	serverUrl := ""
	if serverIndex != -1 {
		serverIndexStart := serverIndex + 8
		serverIndexEnd := serverIndexStart
		for ; serverIndexEnd < len(strClusterConfig); serverIndexEnd++ {
			if string(strClusterConfig[serverIndexEnd]) == "\n" {
				break
			}
		}
		serverUrl = strClusterConfig[serverIndexStart:serverIndexEnd]
	}
	serverUrl = strings.Trim(serverUrl, "\"")

	//get join cluster RestConfig
	clusterRestConfig, err := clientcmd.RESTConfigFromKubeConfig(byteClusterConfig)
	//logrus.Infof(" karmadaConfig   %s ", clusterRestConfig)
	if err != nil {
		logrus.Errorf("clusterRestConfig err %s", err.Error())
		return err
	}

	//get secret
	karmadaSecret, err := managerContext.Core.Secrets("karmada-system").Get("karmada-kubeconfig", metav1.GetOptions{})
	//karmadaSecret, err := secretClient.Get(context.TODO(), "karmada-kubeconfig", metav1.GetOptions{})
	if err != nil {
		karmadaSecret, err = managerContext.Core.Secrets("karmada-system").Get("kubeconfig", metav1.GetOptions{})
		if err != nil {
			logrus.Errorf("karmadaSecret err")
			return err
		}
	}
	//get karmadarestconfig
	karmadaConfig, err := clientcmd.RESTConfigFromKubeConfig(karmadaSecret.Data["kubeconfig"])
	logrus.Infof(" karmadaConfig   %s ", karmadaConfig)
	if err != nil {
		return err
	}
	//namespace?
	err = JoinCluster(karmadaConfig, clusterRestConfig, "karmada-cluster", clusterName)
	if err != nil {
		logrus.Errorf("JoinCluster  ====>   err: %s", err.Error())
		return err
	}
	// 重新构建request的body
	//jsonStr := "{\n    \"metadata\": {\n        \"name\": \"" + clusterName + "\"\n    },\n    \"spec\": {\n        \"apiEndpoint\": \"" + serverUrl + "\",\n        \"secretRef\": {\n            \"name\": \"" + clusterName + "\",\n            \"namespace\": \"karmada-cluster\"\n        },\n        \"syncMode\": \"Push\"\n    }\n}"
	jsonStr := fmt.Sprintf(`{
    "metadata": {
        "name": "%s"
    },
    "spec": {
        "apiEndpoint": "%s",
        "secretRef": {
            "name": "%s",
            "namespace": "karmada-cluster"
        },
        "syncMode": "Push"
    }
}`, clusterName, serverUrl, clusterName)

	req.ContentLength = int64(len(jsonStr))
	req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(jsonStr)))
	req.Header.Set("Content-Type", "application/json")
	logrus.Infof(" r.body   %s ", req.Body)
	return nil
}

type CommandTokenOptions struct {
	TTL                  *metav1.Duration // 令牌失效时间
	Description          string
	Groups               []string
	Usages               []string
	PrintRegisterCommand bool
	parentCommand        string // kubectl karmada 或 karmadactl
}

var opts = &CommandTokenOptions{
	parentCommand: "kubectl karmada", // 或karmadactl
	TTL: &metav1.Duration{
		Duration: 24 * time.Hour,
	},
	// 令牌要认证为的额外组，必须以 "system:bootstrappers:" 开头
	Groups: []string{"system:bootstrappers:karmada:default-cluster-token"},
	// 启动 usage-bootstrap-authentication和 usage-bootstrap-signing
	Usages:               []string{"signing", "authentication"},
	PrintRegisterCommand: true,
}

// NewKarmadaPllJoin : Register cluster with 'Pull' mode
func NewKarmadaPllJoin(w http.ResponseWriter, req *http.Request) (string, error) {
	logrus.Infof("Register cluster with 'Pull' mode")
	//get secret
	karmadaSecret, err := managerContext.Core.Secrets("karmada-system").Get("karmada-kubeconfig", metav1.GetOptions{})
	//karmadaSecret, err := secretClient.Get(context.TODO(), "karmada-kubeconfig", metav1.GetOptions{})
	if err != nil {
		karmadaSecret, err = managerContext.Core.Secrets("karmada-system").Get("kubeconfig", metav1.GetOptions{})
		if err != nil {
			logrus.Errorf("karmadaSecret err: %s", err.Error())
			return "", err
		}
	}
	//get karmadarestconfig
	karmadaConfig, err := clientcmd.RESTConfigFromKubeConfig(karmadaSecret.Data["kubeconfig"])
	if err != nil {
		logrus.Errorf("karmadaConfig err: %s", err.Error())
		return "", err
	}

	client, err := kubernetes.NewForConfig(karmadaConfig)
	if err != nil {
		logrus.Errorf("client err: %s", err.Error())
		return "", err
	}

	joinCommand, err := opts.runCreateToken(w, client)
	if err != nil {
		logrus.Errorf("joinCommand err: %s", err.Error())
		return "", err
	}
	return joinCommand, err
}

func (o *CommandTokenOptions) runCreateToken(w http.ResponseWriter, client kubeclient.Interface) (string, error) {
	bootstrapToken, err := GenerateRandomBootstrapToken(o.TTL, o.Description, o.Groups, o.Usages)
	if err != nil {
		return "", err
	}

	if err = CreateNewToken(client, bootstrapToken); err != nil {
		return "", err
	}

	tokenStr := bootstrapToken.Token.ID + "." + bootstrapToken.Token.Secret

	// if --print-register-command was specified, print a machine-readable full `karmadactl register` command
	// otherwise, just print the token
	if o.PrintRegisterCommand {
		joinCommand, err := GenerateRegisterCommand(KarmadaConfigPath,
			o.parentCommand, tokenStr, "")
		if err != nil {
			return "", fmt.Errorf("failed to get register command, err: %w", err)
		}
		return joinCommand, nil
	} else {
		return tokenStr, nil
	}
}

// GenerateRegisterCommand generate register command that will be printed
func GenerateRegisterCommand(kubeConfig, parentCommand, token string, karmadaContext string) (string, error) {
	// load the kubeconfig file to get the CA certificate and endpoint
	clientConfig, err := clientcmd.LoadFromFile(kubeConfig)
	if err != nil {
		return "", fmt.Errorf("failed to load kubeconfig, err: %w", err)
	}

	// load the cluster config with the given karmada-context
	clusterConfig := GetClusterFromKubeConfig(clientConfig, karmadaContext)
	if clusterConfig == nil {
		return "", fmt.Errorf("failed to get default cluster config")
	}

	// load CA certificates from the kubeconfig (either from PEM data or by file path)
	var caCerts []*x509.Certificate
	if clusterConfig.CertificateAuthorityData != nil {
		caCerts, err = clientcertutil.ParseCertsPEM(clusterConfig.CertificateAuthorityData)
		if err != nil {
			return "", fmt.Errorf("failed to parse CA certificate from kubeconfig, err: %w", err)
		}
	} else if clusterConfig.CertificateAuthority != "" {
		caCerts, err = clientcertutil.CertsFromFile(clusterConfig.CertificateAuthority)
		if err != nil {
			return "", fmt.Errorf("failed to load CA certificate referenced by kubeconfig, err: %w", err)
		}
	} else {
		return "", fmt.Errorf("no CA certificates found in kubeconfig")
	}

	// hash all the CA certs and include their public key pins as trusted values
	publicKeyPins := make([]string, 0, len(caCerts))
	for _, caCert := range caCerts {
		publicKeyPins = append(publicKeyPins, pubkeypin.Hash(caCert))
	}

	return fmt.Sprintf("%s register %s --token %s --discovery-token-ca-cert-hash %s",
		parentCommand, strings.Replace(clusterConfig.Server, "https://", "", -1),
		token, strings.Join(publicKeyPins, ",")), nil
}

// GetClusterFromKubeConfig returns the Cluster of the specified KubeConfig, if karmada-context unset, it will use the current-context
func GetClusterFromKubeConfig(config *clientcmdapi.Config, karmadaContext string) *clientcmdapi.Cluster {
	// If there is an unnamed cluster object, use it
	if config.Clusters[""] != nil {
		return config.Clusters[""]
	}
	if karmadaContext == "" {
		karmadaContext = config.CurrentContext
	}
	if config.Contexts[karmadaContext] != nil {
		return config.Clusters[config.Contexts[karmadaContext].Cluster]
	}
	return nil
}

// Token is a token of the format abcdef.abcdef0123456789 that is used
// for both validation of the practically of the API server from a joining cluster's point
// of view and as an authentication method for the cluster in the bootstrap phase of
// "karmadactl join". This token is and should be short-lived
type Token struct {
	ID     string
	Secret string
}

// BootstrapToken describes one bootstrap token, stored as a Secret in the cluster
type BootstrapToken struct {
	// Token is used for establishing bidirectional trust between clusters and karmada-control-plane.
	// Used for joining clusters to the karmada-control-plane.
	Token *Token
	// Description sets a human-friendly message why this token exists and what it's used
	// for, so other administrators can know its purpose.
	// +optional
	Description string
	// TTL defines the time to live for this token. Defaults to 24h.
	// Expires and TTL are mutually exclusive.
	// +optional
	TTL *metav1.Duration
	// Expires specifies the timestamp when this token expires. Defaults to being set
	// dynamically at runtime based on the TTL. Expires and TTL are mutually exclusive.
	// +optional
	Expires *metav1.Time
	// Usages describes the ways in which this token can be used. Can by default be used
	// for establishing bidirectional trust, but that can be changed here.
	// +optional
	Usages []string
	// Groups specifies the extra groups that this token will authenticate as when/if
	// used for authentication
	// +optional
	Groups []string
}

// GenerateRandomBootstrapToken generate random bootstrap token
func GenerateRandomBootstrapToken(ttl *metav1.Duration, description string, groups, usages []string) (*BootstrapToken, error) {
	tokenStr, err := bootstraputil.GenerateBootstrapToken()
	if err != nil {
		return nil, fmt.Errorf("couldn't generate random token, err: %w", err)
	}

	token, err := NewToken(tokenStr)
	if err != nil {
		return nil, err
	}

	bt := &BootstrapToken{
		Token:       token,
		TTL:         ttl,
		Description: description,
		Groups:      groups,
		Usages:      usages,
	}

	return bt, nil
}

// NewToken converts the given Bootstrap Token as a string
// to the Token object used for serialization/deserialization
// and internal usage. It also automatically validates that the given token
// is of the right format
func NewToken(token string) (*Token, error) {
	substrs := bootstraputil.BootstrapTokenRegexp.FindStringSubmatch(token)
	if len(substrs) != validatedSubstringsSize {
		return nil, fmt.Errorf("the bootstrap token %q was not of the form %q", token, bootstrapapi.BootstrapTokenPattern)
	}

	return &Token{ID: substrs[1], Secret: substrs[2]}, nil
}

// CreateNewToken tries to create a token and fails if one with the same ID already exists
func CreateNewToken(client kubeclient.Interface, token *BootstrapToken) error {
	return UpdateOrCreateToken(client, true, token)
}

// UpdateOrCreateToken attempts to update a token with the given ID, or create if it does not already exist.
func UpdateOrCreateToken(client kubeclient.Interface, failIfExists bool, token *BootstrapToken) error {
	secretName := bootstraputil.BootstrapTokenSecretName(token.Token.ID)
	secret, err := client.CoreV1().Secrets(metav1.NamespaceSystem).Get(context.TODO(), secretName, metav1.GetOptions{})
	if secret != nil && err == nil && failIfExists {
		return fmt.Errorf("a token with id %q already exists", token.Token.ID)
	}

	updatedOrNewSecret := ConvertBootstrapTokenToSecret(token)
	// Try to create or update the token with an exponential backoff
	err = TryRunCommand(func() error {
		if err := CreateOrUpdateSecret(client, updatedOrNewSecret); err != nil {
			return fmt.Errorf("failed to create or update bootstrap token with name %s, err: %w", secretName, err)
		}
		return nil
	}, 5)
	if err != nil {
		return err
	}

	return nil
}

// ConvertBootstrapTokenToSecret converts the given BootstrapToken object to its Secret representation that
// may be submitted to the API Server in order to be stored.
func ConvertBootstrapTokenToSecret(bt *BootstrapToken) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bootstraputil.BootstrapTokenSecretName(bt.Token.ID),
			Namespace: metav1.NamespaceSystem,
		},
		Type: corev1.SecretType(bootstrapapi.SecretTypeBootstrapToken),
		Data: encodeTokenSecretData(bt, time.Now()),
	}
}

// encodeTokenSecretData takes the token discovery object and an optional duration and returns the .Data for the Secret
// now is passed in order to be able to used in unit testing
func encodeTokenSecretData(token *BootstrapToken, now time.Time) map[string][]byte {
	data := map[string][]byte{
		bootstrapapi.BootstrapTokenIDKey:     []byte(token.Token.ID),
		bootstrapapi.BootstrapTokenSecretKey: []byte(token.Token.Secret),
	}

	if len(token.Description) > 0 {
		data[bootstrapapi.BootstrapTokenDescriptionKey] = []byte(token.Description)
	}

	// If for some strange reason both token.TTL and token.Expires would be set
	// (they are mutually exclusive in validation so this shouldn't be the case),
	// token.Expires has higher priority, as can be seen in the logic here.
	if token.Expires != nil {
		// Format the expiration date accordingly
		// TODO: This maybe should be a helper function in bootstraputil?
		expirationString := token.Expires.Time.UTC().Format(time.RFC3339)
		data[bootstrapapi.BootstrapTokenExpirationKey] = []byte(expirationString)
	} else if token.TTL != nil && token.TTL.Duration > 0 {
		// Only if .Expires is unset, TTL might have an effect
		// Get the current time, add the specified duration, and format it accordingly
		expirationString := now.Add(token.TTL.Duration).UTC().Format(time.RFC3339)
		data[bootstrapapi.BootstrapTokenExpirationKey] = []byte(expirationString)
	}

	for _, usage := range token.Usages {
		data[bootstrapapi.BootstrapTokenUsagePrefix+usage] = []byte("true")
	}

	if len(token.Groups) > 0 {
		data[bootstrapapi.BootstrapTokenExtraGroupsKey] = []byte(strings.Join(token.Groups, ","))
	}
	return data
}

// TryRunCommand runs a function a maximum of failureThreshold times, and retries on error. If failureThreshold is hit; the last error is returned
func TryRunCommand(f func() error, failureThreshold int) error {
	backoff := wait.Backoff{
		Duration: 5 * time.Second,
		Factor:   2, // double the timeout for every failure
		Steps:    failureThreshold,
	}
	return wait.ExponentialBackoff(backoff, func() (bool, error) {
		err := f()
		if err != nil {
			// Retry until the timeout
			return false, nil
		}
		// The last f() call was a success, return cleanly
		return true, nil
	})
}

// CreateOrUpdateSecret creates a Secret if the target resource doesn't exist.
// If the resource exists already, this function will update the resource instead.
func CreateOrUpdateSecret(client kubeclient.Interface, secret *corev1.Secret) error {
	if _, err := client.CoreV1().Secrets(secret.Namespace).Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("unable to create Secret: %v", err)
		}

		existSecret, err := client.CoreV1().Secrets(secret.Namespace).Get(context.TODO(), secret.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		secret.ResourceVersion = existSecret.ResourceVersion

		if _, err := client.CoreV1().Secrets(secret.Namespace).Update(context.TODO(), secret, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("unable to update Secret: %v", err)
		}
	}
	logrus.Infof("Secret %s/%s has been created or updated.", secret.Namespace, secret.Name)
	return nil
}

func errorHandler() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		fmt.Printf("Got error while modifying response: %v \n", err)
		return
	}
}

// 用于返回pull模式的集群注册指令
func NewKarmadaPullJoinHandler(w http.ResponseWriter, request *http.Request) {
	// The request to register the cluster with Pull mode
	if request.Method == "GET" && strings.Contains(request.RequestURI, "/multicluster/cluster.karmada.io/v1alpha1/clusters/pull") {
		joinCommand, err := NewKarmadaPllJoin(w, request)
		if err != nil {
			logrus.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			_, err = w.Write([]byte(err.Error()))
			if err != nil {
				logrus.Error(err.Error())
			}
			return
		}

		joinCommand = joinCommand + " --cluster-name=<cluster name>"
		_, err = w.Write([]byte(joinCommand))
		if err != nil {
			logrus.Error(err.Error())
		}
	}
}

func ProxyRequestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, request *http.Request) {
		// 去除url中的多余前缀
		request.URL.Path = strings.TrimPrefix(request.URL.Path, "/karmada")

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
	if _, err = util2.EnsureNamespaceExist(controlPlaneKubeClient, clusterNamespace, false); err != nil {
		logrus.Infof("joining cluster config. endpoint: %s", clusterConfig.Host)
		return err
	}
	logrus.Infof("joining cluster config. endpoint: %s", clusterConfig.Host)
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
	secret, err := util2.CreateSecret(controlPlaneKubeClient, secret)
	if err != nil {
		return fmt.Errorf("failed to create secret in control plane. error: %v", err)
	}

	// create secret to store impersonation info in control plane
	impersonatorSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: clusterNamespace,
			Name:      names2.GenerateImpersonationSecretName(clusterName),
		},
		Data: map[string][]byte{
			SecretTokenKey: clusterImpersonatorSecret.Data[SecretTokenKey],
		},
	}
	//2、创建impersonatorSecret在 host集群中
	impersonatorSecret, err = util2.CreateSecret(controlPlaneKubeClient, impersonatorSecret)
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

// 从成员集群获取凭证
func obtainCredentialsFromMemberCluster(clusterKubeClient kubeclient.Interface, clusterNamespace, clusterName string, dryRun bool) (*corev1.Secret, *corev1.Secret, error) {
	var err error

	// ensure namespace where the karmada control plane credential be stored exists in cluster.
	if _, err = util2.EnsureNamespaceExist(clusterKubeClient, clusterNamespace, dryRun); err != nil {
		return nil, nil, err
	}

	// create a ServiceAccount in cluster.
	serviceAccountObj := &corev1.ServiceAccount{}
	serviceAccountObj.Namespace = clusterNamespace
	serviceAccountObj.Name = names2.GenerateServiceAccountName(clusterName)
	if serviceAccountObj, err = util2.EnsureServiceAccountExist(clusterKubeClient, serviceAccountObj, dryRun); err != nil {
		return nil, nil, err
	}

	// create a ServiceAccount for impersonation in cluster.
	impersonationSA := &corev1.ServiceAccount{}
	impersonationSA.Namespace = clusterNamespace
	impersonationSA.Name = names2.GenerateServiceAccountName("impersonator")
	if impersonationSA, err = util2.EnsureServiceAccountExist(clusterKubeClient, impersonationSA, dryRun); err != nil {
		return nil, nil, err
	}

	// create a ClusterRole in cluster.
	clusterRole := &rbacv1.ClusterRole{}
	clusterRole.Name = names2.GenerateRoleName(serviceAccountObj.Name)
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
	clusterSecret, err := util2.WaitForServiceAccountSecretCreation(clusterKubeClient, serviceAccountObj)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get serviceAccount secret from cluster(%s), error: %v", clusterName, err)
	}

	impersonatorSecret, err := util2.WaitForServiceAccountSecretCreation(clusterKubeClient, impersonationSA)
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

	exist, err := util2.IsClusterRoleExist(client, clusterRole.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check if ClusterRole exist. ClusterRole: %s, error: %v", clusterRole.Name, err)
	}
	if exist {
		logrus.Infof("ensure ClusterRole succeed as already exist. ClusterRole: %s", clusterRole.Name)
		return clusterRole, nil
	}

	createdObj, err := util2.CreateClusterRole(client, clusterRole)
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

	exist, err := util2.IsClusterRoleBindingExist(client, clusterRoleBinding.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check if ClusterRole exist. ClusterRole: %s, error: %v", clusterRoleBinding.Name, err)
	}
	if exist {
		logrus.Infof("ensure ClusterRole succeed as already exist. ClusterRole: %s", clusterRoleBinding.Name)
		return clusterRoleBinding, nil
	}

	createdObj, err := util2.CreateClusterRoleBinding(client, clusterRoleBinding)
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
