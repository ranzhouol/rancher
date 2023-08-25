package names

import (
	"fmt"
	"strings"
)

const (
	// KubernetesReservedNSPrefix is the prefix of namespace which reserved by Kubernetes system, such as:
	// - kube-system
	// - kube-public
	// - kube-node-lease
	KubernetesReservedNSPrefix = "kube-"
	// NamespaceKarmadaSystem is reserved namespace
	NamespaceKarmadaSystem = "karmada-system"
	// NamespaceKarmadaCluster is reserved namespace
	NamespaceKarmadaCluster = "karmada-cluster"
	// NamespaceDefault is reserved namespace
	NamespaceDefault = "default"
)

// ExecutionSpacePrefix is the prefix of execution space
const ExecutionSpacePrefix = "karmada-es-"

// endpointSlicePrefix is the prefix of collected EndpointSlice from member clusters.
const endpointSlicePrefix = "imported"

// endpointSlicePrefix is the prefix of service derived from ServiceImport.
const derivedServicePrefix = "derived"

// estimatorServicePrefix is the prefix of scheduler estimator service name.
const estimatorServicePrefix = "karmada-scheduler-estimator"

// GenerateExecutionSpaceName generates execution space name for the given member cluster
func GenerateExecutionSpaceName(clusterName string) (string, error) {
	if clusterName == "" {
		return "", fmt.Errorf("the member cluster name is empty")
	}
	executionSpace := ExecutionSpacePrefix + clusterName
	return executionSpace, nil
}

// GetClusterName returns member cluster name for the given execution space
func GetClusterName(executionSpaceName string) (string, error) {
	if !strings.HasPrefix(executionSpaceName, ExecutionSpacePrefix) {
		return "", fmt.Errorf("the execution space name is in wrong format")
	}
	return strings.TrimPrefix(executionSpaceName, ExecutionSpacePrefix), nil
}

// GenerateBindingName will generate binding name by kind and name
func GenerateBindingName(kind, name string) string {
	return strings.ToLower(name + "-" + kind)
}

// GenerateServiceAccountName generates the name of a ServiceAccount.
func GenerateServiceAccountName(clusterName string) string {
	return fmt.Sprintf("%s-%s", "karmada", clusterName)
}

// GenerateRoleName generates the name of a Role or ClusterRole.
func GenerateRoleName(serviceAccountName string) string {
	return fmt.Sprintf("karmada-controller-manager:%s", serviceAccountName)
}

// GenerateEndpointSliceName generates the name of collected EndpointSlice.
func GenerateEndpointSliceName(endpointSliceName string, cluster string) string {
	return fmt.Sprintf("%s-%s-%s", endpointSlicePrefix, cluster, endpointSliceName)
}

// GenerateDerivedServiceName generates the service name derived from ServiceImport.
func GenerateDerivedServiceName(serviceName string) string {
	return fmt.Sprintf("%s-%s", derivedServicePrefix, serviceName)
}

// GenerateEstimatorServiceName generates the gRPC scheduler estimator service name which belongs to a cluster.
func GenerateEstimatorServiceName(clusterName string) string {
	return fmt.Sprintf("%s-%s", estimatorServicePrefix, clusterName)
}

// IsReservedNamespace return whether it is a reserved namespace
func IsReservedNamespace(namespace string) bool {
	return namespace == NamespaceKarmadaSystem ||
		namespace == NamespaceKarmadaCluster ||
		strings.HasPrefix(namespace, ExecutionSpacePrefix) ||
		strings.HasPrefix(namespace, KubernetesReservedNSPrefix)
}

// GenerateImpersonationSecretName generates the secret name of impersonation secret.
func GenerateImpersonationSecretName(clusterName string) string {
	return fmt.Sprintf("%s-impersonator", clusterName)
}