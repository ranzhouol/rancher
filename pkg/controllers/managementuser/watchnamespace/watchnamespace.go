package watchnamespace

import (
	"context"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

type Controller struct {
	ctx      context.Context
	workload *config.UserContext
}

var (
	// 需要放置到 System 项目下的命名空间
	SystemNamespaces = []string{"prometheus", "karmada-system"}
)

func Register(ctx context.Context, workload *config.UserContext) {
	c := &Controller{
		ctx:      ctx,
		workload: workload,
	}
	c.workload.Core.Namespaces("").AddHandler(ctx, "namespaceEdgesphereSyncHandler", c.sync)
}

func (c *Controller) sync(key string, obj *v1.Namespace) (runtime.Object, error) {
	if obj == nil || obj.DeletionTimestamp != nil ||
		obj.Status.Phase == v1.NamespaceTerminating {
		return nil, nil
	}

	return nil, c.NamespaceAddAnnotation()
}

func (c *Controller) NamespaceAddAnnotation() error {
	namespacewatch, err := c.workload.Management.Core.Namespaces("").Watch(metav1.ListOptions{})
	if err != nil {
		logrus.Errorf(err.Error())
	}

	clusterName := c.workload.ClusterName
	go c.AddClusterName(namespacewatch, clusterName)
	return nil
}

func (c *Controller) AddClusterName(namespacewatch watch.Interface, clusterName string) {
	for ns := range namespacewatch.ResultChan() {
		namespace, ok := ns.Object.(*corev1.Namespace)
		if ok && namespace.Status.Phase == "Active" {
			annotation := namespace.GetAnnotations()
			if annotation == nil {
				annotation = map[string]string{}
				namespace.SetAnnotations(annotation)
			}
			if value, ok := annotation["clusterName"]; !ok || value != clusterName {
				annotation["clusterName"] = clusterName
				c.workload.Management.Core.Namespaces("").Update(namespace)
			}
		}
	}
}

func (c *Controller) AddToSystem(obj *v1.Namespace, clusterName string) {
	for _, sns := range SystemNamespaces {
		if obj.ObjectMeta.Name == sns {

		}
	}
}
