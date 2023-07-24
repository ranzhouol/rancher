/*
Copyright 2023 Rancher Labs, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by main. DO NOT EDIT.

package v1alpha4

import (
	"context"
	"time"

	"github.com/rancher/lasso/pkg/client"
	"github.com/rancher/lasso/pkg/controller"
	"github.com/rancher/wrangler/pkg/apply"
	"github.com/rancher/wrangler/pkg/condition"
	"github.com/rancher/wrangler/pkg/generic"
	"github.com/rancher/wrangler/pkg/kv"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	v1alpha4 "sigs.k8s.io/cluster-api/api/v1alpha4"
)

type MachineDeploymentHandler func(string, *v1alpha4.MachineDeployment) (*v1alpha4.MachineDeployment, error)

type MachineDeploymentController interface {
	generic.ControllerMeta
	MachineDeploymentClient

	OnChange(ctx context.Context, name string, sync MachineDeploymentHandler)
	OnRemove(ctx context.Context, name string, sync MachineDeploymentHandler)
	Enqueue(namespace, name string)
	EnqueueAfter(namespace, name string, duration time.Duration)

	Cache() MachineDeploymentCache
}

type MachineDeploymentClient interface {
	Create(*v1alpha4.MachineDeployment) (*v1alpha4.MachineDeployment, error)
	Update(*v1alpha4.MachineDeployment) (*v1alpha4.MachineDeployment, error)
	UpdateStatus(*v1alpha4.MachineDeployment) (*v1alpha4.MachineDeployment, error)
	Delete(namespace, name string, options *metav1.DeleteOptions) error
	Get(namespace, name string, options metav1.GetOptions) (*v1alpha4.MachineDeployment, error)
	List(namespace string, opts metav1.ListOptions) (*v1alpha4.MachineDeploymentList, error)
	Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error)
	Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha4.MachineDeployment, err error)
}

type MachineDeploymentCache interface {
	Get(namespace, name string) (*v1alpha4.MachineDeployment, error)
	List(namespace string, selector labels.Selector) ([]*v1alpha4.MachineDeployment, error)

	AddIndexer(indexName string, indexer MachineDeploymentIndexer)
	GetByIndex(indexName, key string) ([]*v1alpha4.MachineDeployment, error)
}

type MachineDeploymentIndexer func(obj *v1alpha4.MachineDeployment) ([]string, error)

type machineDeploymentController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewMachineDeploymentController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) MachineDeploymentController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &machineDeploymentController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromMachineDeploymentHandlerToHandler(sync MachineDeploymentHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v1alpha4.MachineDeployment
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v1alpha4.MachineDeployment))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *machineDeploymentController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v1alpha4.MachineDeployment))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateMachineDeploymentDeepCopyOnChange(client MachineDeploymentClient, obj *v1alpha4.MachineDeployment, handler func(obj *v1alpha4.MachineDeployment) (*v1alpha4.MachineDeployment, error)) (*v1alpha4.MachineDeployment, error) {
	if obj == nil {
		return obj, nil
	}

	copyObj := obj.DeepCopy()
	newObj, err := handler(copyObj)
	if newObj != nil {
		copyObj = newObj
	}
	if obj.ResourceVersion == copyObj.ResourceVersion && !equality.Semantic.DeepEqual(obj, copyObj) {
		return client.Update(copyObj)
	}

	return copyObj, err
}

func (c *machineDeploymentController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *machineDeploymentController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *machineDeploymentController) OnChange(ctx context.Context, name string, sync MachineDeploymentHandler) {
	c.AddGenericHandler(ctx, name, FromMachineDeploymentHandlerToHandler(sync))
}

func (c *machineDeploymentController) OnRemove(ctx context.Context, name string, sync MachineDeploymentHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromMachineDeploymentHandlerToHandler(sync)))
}

func (c *machineDeploymentController) Enqueue(namespace, name string) {
	c.controller.Enqueue(namespace, name)
}

func (c *machineDeploymentController) EnqueueAfter(namespace, name string, duration time.Duration) {
	c.controller.EnqueueAfter(namespace, name, duration)
}

func (c *machineDeploymentController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *machineDeploymentController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *machineDeploymentController) Cache() MachineDeploymentCache {
	return &machineDeploymentCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *machineDeploymentController) Create(obj *v1alpha4.MachineDeployment) (*v1alpha4.MachineDeployment, error) {
	result := &v1alpha4.MachineDeployment{}
	return result, c.client.Create(context.TODO(), obj.Namespace, obj, result, metav1.CreateOptions{})
}

func (c *machineDeploymentController) Update(obj *v1alpha4.MachineDeployment) (*v1alpha4.MachineDeployment, error) {
	result := &v1alpha4.MachineDeployment{}
	return result, c.client.Update(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *machineDeploymentController) UpdateStatus(obj *v1alpha4.MachineDeployment) (*v1alpha4.MachineDeployment, error) {
	result := &v1alpha4.MachineDeployment{}
	return result, c.client.UpdateStatus(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *machineDeploymentController) Delete(namespace, name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), namespace, name, *options)
}

func (c *machineDeploymentController) Get(namespace, name string, options metav1.GetOptions) (*v1alpha4.MachineDeployment, error) {
	result := &v1alpha4.MachineDeployment{}
	return result, c.client.Get(context.TODO(), namespace, name, result, options)
}

func (c *machineDeploymentController) List(namespace string, opts metav1.ListOptions) (*v1alpha4.MachineDeploymentList, error) {
	result := &v1alpha4.MachineDeploymentList{}
	return result, c.client.List(context.TODO(), namespace, result, opts)
}

func (c *machineDeploymentController) Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), namespace, opts)
}

func (c *machineDeploymentController) Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (*v1alpha4.MachineDeployment, error) {
	result := &v1alpha4.MachineDeployment{}
	return result, c.client.Patch(context.TODO(), namespace, name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type machineDeploymentCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *machineDeploymentCache) Get(namespace, name string) (*v1alpha4.MachineDeployment, error) {
	obj, exists, err := c.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v1alpha4.MachineDeployment), nil
}

func (c *machineDeploymentCache) List(namespace string, selector labels.Selector) (ret []*v1alpha4.MachineDeployment, err error) {

	err = cache.ListAllByNamespace(c.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha4.MachineDeployment))
	})

	return ret, err
}

func (c *machineDeploymentCache) AddIndexer(indexName string, indexer MachineDeploymentIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v1alpha4.MachineDeployment))
		},
	}))
}

func (c *machineDeploymentCache) GetByIndex(indexName, key string) (result []*v1alpha4.MachineDeployment, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v1alpha4.MachineDeployment, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v1alpha4.MachineDeployment))
	}
	return result, nil
}

type MachineDeploymentStatusHandler func(obj *v1alpha4.MachineDeployment, status v1alpha4.MachineDeploymentStatus) (v1alpha4.MachineDeploymentStatus, error)

type MachineDeploymentGeneratingHandler func(obj *v1alpha4.MachineDeployment, status v1alpha4.MachineDeploymentStatus) ([]runtime.Object, v1alpha4.MachineDeploymentStatus, error)

func RegisterMachineDeploymentStatusHandler(ctx context.Context, controller MachineDeploymentController, condition condition.Cond, name string, handler MachineDeploymentStatusHandler) {
	statusHandler := &machineDeploymentStatusHandler{
		client:    controller,
		condition: condition,
		handler:   handler,
	}
	controller.AddGenericHandler(ctx, name, FromMachineDeploymentHandlerToHandler(statusHandler.sync))
}

func RegisterMachineDeploymentGeneratingHandler(ctx context.Context, controller MachineDeploymentController, apply apply.Apply,
	condition condition.Cond, name string, handler MachineDeploymentGeneratingHandler, opts *generic.GeneratingHandlerOptions) {
	statusHandler := &machineDeploymentGeneratingHandler{
		MachineDeploymentGeneratingHandler: handler,
		apply:                              apply,
		name:                               name,
		gvk:                                controller.GroupVersionKind(),
	}
	if opts != nil {
		statusHandler.opts = *opts
	}
	controller.OnChange(ctx, name, statusHandler.Remove)
	RegisterMachineDeploymentStatusHandler(ctx, controller, condition, name, statusHandler.Handle)
}

type machineDeploymentStatusHandler struct {
	client    MachineDeploymentClient
	condition condition.Cond
	handler   MachineDeploymentStatusHandler
}

func (a *machineDeploymentStatusHandler) sync(key string, obj *v1alpha4.MachineDeployment) (*v1alpha4.MachineDeployment, error) {
	if obj == nil {
		return obj, nil
	}

	origStatus := obj.Status.DeepCopy()
	obj = obj.DeepCopy()
	newStatus, err := a.handler(obj, obj.Status)
	if err != nil {
		// Revert to old status on error
		newStatus = *origStatus.DeepCopy()
	}

	if a.condition != "" {
		if errors.IsConflict(err) {
			a.condition.SetError(&newStatus, "", nil)
		} else {
			a.condition.SetError(&newStatus, "", err)
		}
	}
	if !equality.Semantic.DeepEqual(origStatus, &newStatus) {
		if a.condition != "" {
			// Since status has changed, update the lastUpdatedTime
			a.condition.LastUpdated(&newStatus, time.Now().UTC().Format(time.RFC3339))
		}

		var newErr error
		obj.Status = newStatus
		newObj, newErr := a.client.UpdateStatus(obj)
		if err == nil {
			err = newErr
		}
		if newErr == nil {
			obj = newObj
		}
	}
	return obj, err
}

type machineDeploymentGeneratingHandler struct {
	MachineDeploymentGeneratingHandler
	apply apply.Apply
	opts  generic.GeneratingHandlerOptions
	gvk   schema.GroupVersionKind
	name  string
}

func (a *machineDeploymentGeneratingHandler) Remove(key string, obj *v1alpha4.MachineDeployment) (*v1alpha4.MachineDeployment, error) {
	if obj != nil {
		return obj, nil
	}

	obj = &v1alpha4.MachineDeployment{}
	obj.Namespace, obj.Name = kv.RSplit(key, "/")
	obj.SetGroupVersionKind(a.gvk)

	return nil, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects()
}

func (a *machineDeploymentGeneratingHandler) Handle(obj *v1alpha4.MachineDeployment, status v1alpha4.MachineDeploymentStatus) (v1alpha4.MachineDeploymentStatus, error) {
	if !obj.DeletionTimestamp.IsZero() {
		return status, nil
	}

	objs, newStatus, err := a.MachineDeploymentGeneratingHandler(obj, status)
	if err != nil {
		return newStatus, err
	}

	return newStatus, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects(objs...)
}
