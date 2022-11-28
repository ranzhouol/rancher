/*
Copyright 2022 Rancher Labs, Inc.

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

// Code generated by C:\Users\chongbzh\AppData\Local\Temp\___go_build_github_com_rancher_rancher_pkg_codegen.exe. DO NOT EDIT.

package v3

import (
	"context"
	"time"

	"github.com/rancher/lasso/pkg/client"
	"github.com/rancher/lasso/pkg/controller"
	v3 "github.com/rancher/rancher/pkg/apis/project.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/generic"
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
)

type SSHAuthHandler func(string, *v3.SSHAuth) (*v3.SSHAuth, error)

type SSHAuthController interface {
	generic.ControllerMeta
	SSHAuthClient

	OnChange(ctx context.Context, name string, sync SSHAuthHandler)
	OnRemove(ctx context.Context, name string, sync SSHAuthHandler)
	Enqueue(namespace, name string)
	EnqueueAfter(namespace, name string, duration time.Duration)

	Cache() SSHAuthCache
}

type SSHAuthClient interface {
	Create(*v3.SSHAuth) (*v3.SSHAuth, error)
	Update(*v3.SSHAuth) (*v3.SSHAuth, error)

	Delete(namespace, name string, options *metav1.DeleteOptions) error
	Get(namespace, name string, options metav1.GetOptions) (*v3.SSHAuth, error)
	List(namespace string, opts metav1.ListOptions) (*v3.SSHAuthList, error)
	Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error)
	Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (result *v3.SSHAuth, err error)
}

type SSHAuthCache interface {
	Get(namespace, name string) (*v3.SSHAuth, error)
	List(namespace string, selector labels.Selector) ([]*v3.SSHAuth, error)

	AddIndexer(indexName string, indexer SSHAuthIndexer)
	GetByIndex(indexName, key string) ([]*v3.SSHAuth, error)
}

type SSHAuthIndexer func(obj *v3.SSHAuth) ([]string, error)

type sSHAuthController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewSSHAuthController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) SSHAuthController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &sSHAuthController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromSSHAuthHandlerToHandler(sync SSHAuthHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v3.SSHAuth
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v3.SSHAuth))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *sSHAuthController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v3.SSHAuth))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateSSHAuthDeepCopyOnChange(client SSHAuthClient, obj *v3.SSHAuth, handler func(obj *v3.SSHAuth) (*v3.SSHAuth, error)) (*v3.SSHAuth, error) {
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

func (c *sSHAuthController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *sSHAuthController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *sSHAuthController) OnChange(ctx context.Context, name string, sync SSHAuthHandler) {
	c.AddGenericHandler(ctx, name, FromSSHAuthHandlerToHandler(sync))
}

func (c *sSHAuthController) OnRemove(ctx context.Context, name string, sync SSHAuthHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromSSHAuthHandlerToHandler(sync)))
}

func (c *sSHAuthController) Enqueue(namespace, name string) {
	c.controller.Enqueue(namespace, name)
}

func (c *sSHAuthController) EnqueueAfter(namespace, name string, duration time.Duration) {
	c.controller.EnqueueAfter(namespace, name, duration)
}

func (c *sSHAuthController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *sSHAuthController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *sSHAuthController) Cache() SSHAuthCache {
	return &sSHAuthCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *sSHAuthController) Create(obj *v3.SSHAuth) (*v3.SSHAuth, error) {
	result := &v3.SSHAuth{}
	return result, c.client.Create(context.TODO(), obj.Namespace, obj, result, metav1.CreateOptions{})
}

func (c *sSHAuthController) Update(obj *v3.SSHAuth) (*v3.SSHAuth, error) {
	result := &v3.SSHAuth{}
	return result, c.client.Update(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *sSHAuthController) Delete(namespace, name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), namespace, name, *options)
}

func (c *sSHAuthController) Get(namespace, name string, options metav1.GetOptions) (*v3.SSHAuth, error) {
	result := &v3.SSHAuth{}
	return result, c.client.Get(context.TODO(), namespace, name, result, options)
}

func (c *sSHAuthController) List(namespace string, opts metav1.ListOptions) (*v3.SSHAuthList, error) {
	result := &v3.SSHAuthList{}
	return result, c.client.List(context.TODO(), namespace, result, opts)
}

func (c *sSHAuthController) Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), namespace, opts)
}

func (c *sSHAuthController) Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (*v3.SSHAuth, error) {
	result := &v3.SSHAuth{}
	return result, c.client.Patch(context.TODO(), namespace, name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type sSHAuthCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *sSHAuthCache) Get(namespace, name string) (*v3.SSHAuth, error) {
	obj, exists, err := c.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v3.SSHAuth), nil
}

func (c *sSHAuthCache) List(namespace string, selector labels.Selector) (ret []*v3.SSHAuth, err error) {

	err = cache.ListAllByNamespace(c.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v3.SSHAuth))
	})

	return ret, err
}

func (c *sSHAuthCache) AddIndexer(indexName string, indexer SSHAuthIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v3.SSHAuth))
		},
	}))
}

func (c *sSHAuthCache) GetByIndex(indexName, key string) (result []*v3.SSHAuth, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v3.SSHAuth, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v3.SSHAuth))
	}
	return result, nil
}
