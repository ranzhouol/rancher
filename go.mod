module github.com/rancher/rancher

go 1.16

replace (
	git.apache.org/thrift.git => github.com/apache/thrift v0.12.0

	github.com/docker/distribution => github.com/docker/distribution v2.7.1+incompatible // oras dep requires a replace is set
	github.com/docker/docker => github.com/docker/docker v20.10.6+incompatible // oras dep requires a replace is set

	github.com/knative/pkg => github.com/rancher/pkg v0.0.0-20190514055449-b30ab9de040e
	github.com/matryer/moq => github.com/rancher/moq v0.0.0-20200712062324-13d1f37d2d77
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.1
	github.com/rancher/rancher/pkg/apis => ./pkg/apis
	github.com/rancher/rancher/pkg/client => ./pkg/client
	helm.sh/helm/v3 => github.com/rancher/helm/v3 v3.7.1-rancher.1

	k8s.io/api => k8s.io/api v0.22.3
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.22.3
	k8s.io/apimachinery => k8s.io/apimachinery v0.22.3
	k8s.io/apiserver => k8s.io/apiserver v0.22.3
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.22.3
	k8s.io/client-go => github.com/rancher/client-go v1.22.3-rancher.1
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.22.3
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.22.3
	k8s.io/code-generator => k8s.io/code-generator v0.22.3
	k8s.io/component-base => k8s.io/component-base v0.22.3
	k8s.io/component-helpers => k8s.io/component-helpers v0.22.3
	k8s.io/controller-manager => k8s.io/controller-manager v0.22.3
	k8s.io/cri-api => k8s.io/cri-api v0.22.3
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.22.3
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.22.3
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.22.3
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.22.3
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.22.3
	k8s.io/kubectl => k8s.io/kubectl v0.22.3
	k8s.io/kubelet => k8s.io/kubelet v0.22.3
	k8s.io/kubernetes => k8s.io/kubernetes v1.22.3
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.22.3
	k8s.io/metrics => k8s.io/metrics v0.22.3
	k8s.io/mount-utils => k8s.io/mount-utils v0.22.3
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.22.0
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.22.3
	sigs.k8s.io/cluster-api => sigs.k8s.io/cluster-api v0.4.4
)

require (
	github.com/Azure/azure-sdk-for-go v55.7.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.19
	github.com/Azure/go-autorest/autorest/adal v0.9.14
	github.com/Azure/go-autorest/autorest/to v0.4.1-0.20210111195520-9fc88b15294e
	github.com/BurntSushi/toml v1.0.0 // indirect
	github.com/DataDog/zstd v1.4.5 // indirect
	github.com/Masterminds/semver/v3 v3.1.1
	github.com/Masterminds/sprig/v3 v3.2.2
	github.com/aws/aws-sdk-go v1.42.27
	github.com/bep/debounce v1.2.0
	github.com/blang/semver v3.5.1+incompatible
	github.com/coreos/go-iptables v0.6.0
	github.com/coreos/go-oidc/v3 v3.0.0
	github.com/coreos/go-semver v0.3.0
	github.com/creasty/defaults v1.5.2
	github.com/crewjam/saml v0.4.5
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v20.10.6+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/ehazlett/simplelog v0.0.0-20200226020431-d374894e92a4
	github.com/evanphx/json-patch v4.12.0+incompatible
	github.com/garyburd/redigo v1.6.2 // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/go-asn1-ber/asn1-ber v1.5.3 // indirect
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/go-logr/logr v1.2.0
	github.com/gofrs/flock v0.8.1 // indirect
	github.com/golang-jwt/jwt v3.2.1+incompatible
	github.com/golang/protobuf v1.5.2
	github.com/google/go-github v17.0.0+incompatible
	github.com/google/go-querystring v1.0.0
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.2
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/heptio/authenticator v0.0.0-20180409043135-d282f87a1972
	github.com/knative/pkg v0.0.0-20190817231834-12ee58e32cc8
	github.com/lib/pq v1.10.3 // indirect
	github.com/mattn/go-colorable v0.1.12
	github.com/mcuadros/go-version v0.0.0-20180611085657-6d5863ca60fa
	github.com/minio/minio-go/v7 v7.0.10
	github.com/mitchellh/mapstructure v1.4.3
	github.com/moby/locker v1.0.1
	github.com/mrjones/oauth v0.0.0-20180629183705-f4e24b6d100c
	github.com/oracle/oci-go-sdk v18.0.0+incompatible
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.52.0
	github.com/prometheus/client_golang v1.12.1
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.32.1
	github.com/rancher/aks-operator v1.0.3
	github.com/rancher/apiserver v0.0.0-20211025232108-df28932a5627
	github.com/rancher/channelserver v0.5.1-0.20210618172430-5cbefd383369
	github.com/rancher/dynamiclistener v0.3.1-0.20211104200948-cd5d71f2fe95
	github.com/rancher/eks-operator v1.1.2
	github.com/rancher/fleet/pkg/apis v0.0.0-20210918015053-5a141a6b18f0
	github.com/rancher/gke-operator v1.1.2
	github.com/rancher/kubernetes-provider-detector v0.1.5
	github.com/rancher/lasso v0.0.0-20211217013041-3c6118a30611
	github.com/rancher/lasso/controller-runtime v0.0.0-20211217013041-3c6118a30611
	github.com/rancher/machine v0.15.0-rancher73
	github.com/rancher/norman v0.0.0-20211201154850-abe17976423e
	github.com/rancher/rancher/pkg/apis v0.0.0
	github.com/rancher/rancher/pkg/client v0.0.0
	github.com/rancher/rdns-server v0.0.0-20180802070304-bf662911db6a
	github.com/rancher/remotedialer v0.2.6-0.20220120012928-4ea2198e0966
	github.com/rancher/rke v1.3.7
	github.com/rancher/security-scan v0.1.7-0.20200222041501-f7377f127168
	github.com/rancher/steve v0.0.0-20210915171517-ae8b16260899
	github.com/rancher/system-upgrade-controller/pkg/apis v0.0.0-20210727200656-10b094e30007
	github.com/rancher/wrangler v0.8.10
	github.com/robfig/cron v1.1.0
	github.com/rs/xid v1.3.0 // indirect
	github.com/russellhaering/goxmldsig v1.1.1 // indirect
	github.com/satori/go.uuid v1.2.0
	github.com/segmentio/kafka-go v0.0.0-20190411192201-218fd49cff39
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/afero v1.8.0 // indirect
	github.com/spf13/cobra v1.3.0 // indirect
	github.com/spf13/viper v1.10.1 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/tomnomnom/linkheader v0.0.0-20180905144013-02ca5825eb80
	github.com/urfave/cli v1.22.2
	github.com/vishvananda/netlink v1.1.1-0.20201228183132-77e4d032a06a
	github.com/vmihailenco/msgpack v4.0.1+incompatible
	github.com/vmware/govmomi v0.26.0
	github.com/vmware/kube-fluentd-operator v0.0.0-20190307154903-bf9de7e79eaf
	github.com/xanzy/go-gitlab v0.0.0-20180830102804-feb856f4760f
	github.com/xdg/scram v0.0.0-20180814205039-7eeb5667e42c // indirect
	github.com/xdg/stringprep v1.0.0 // indirect
	github.com/yvasiyarov/go-metrics v0.0.0-20150112132944-c25f46c4b940 // indirect
	github.com/yvasiyarov/gorelic v0.0.7 // indirect
	github.com/yvasiyarov/newrelic_platform_go v0.0.0-20160601141957-9c099fbc30e9 // indirect
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292
	golang.org/x/mod v0.6.0-dev.0.20220106191415-9b9b3d81d5e3
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/tools v0.1.10 // indirect
	google.golang.org/api v0.63.0
	google.golang.org/grpc v1.43.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	gopkg.in/ini.v1 v1.66.3 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0
	helm.sh/helm/v3 v3.7.1
	k8s.io/api v0.24.2
	k8s.io/apiextensions-apiserver v0.24.2
	k8s.io/apimachinery v0.24.2
	k8s.io/apiserver v0.24.2
	k8s.io/cli-runtime v0.24.2
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/cluster-bootstrap v0.23.4 // indirect
	k8s.io/code-generator v0.23.4 // indirect
	k8s.io/component-helpers v0.23.4 // indirect
	k8s.io/gengo v0.0.0-20211129171323-c02415ce4185
	k8s.io/helm v2.16.7+incompatible
	k8s.io/kube-aggregator v0.24.2
	k8s.io/kubectl v0.24.2
	k8s.io/kubernetes v1.21.0
	k8s.io/utils v0.0.0-20220210201930-3a6ce19ff2f9
	sigs.k8s.io/apiserver-network-proxy/konnectivity-client v0.0.27 // indirect
	sigs.k8s.io/aws-iam-authenticator v0.5.1
	sigs.k8s.io/cluster-api v0.4.4
	sigs.k8s.io/controller-runtime v0.11.1
	sigs.k8s.io/kustomize/api v0.10.1 // indirect
	sigs.k8s.io/yaml v1.3.0
)
