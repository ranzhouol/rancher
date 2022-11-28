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
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
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

type SamlProviderHandler func(string, *v3.SamlProvider) (*v3.SamlProvider, error)

type SamlProviderController interface {
	generic.ControllerMeta
	SamlProviderClient

	OnChange(ctx context.Context, name string, sync SamlProviderHandler)
	OnRemove(ctx context.Context, name string, sync SamlProviderHandler)
	Enqueue(name string)
	EnqueueAfter(name string, duration time.Duration)

	Cache() SamlProviderCache
}

type SamlProviderClient interface {
	Create(*v3.SamlProvider) (*v3.SamlProvider, error)
	Update(*v3.SamlProvider) (*v3.SamlProvider, error)

	Delete(name string, options *metav1.DeleteOptions) error
	Get(name string, options metav1.GetOptions) (*v3.SamlProvider, error)
	List(opts metav1.ListOptions) (*v3.SamlProviderList, error)
	Watch(opts metav1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v3.SamlProvider, err error)
}

type SamlProviderCache interface {
	Get(name string) (*v3.SamlProvider, error)
	List(selector labels.Selector) ([]*v3.SamlProvider, error)

	AddIndexer(indexName string, indexer SamlProviderIndexer)
	GetByIndex(indexName, key string) ([]*v3.SamlProvider, error)
}

type SamlProviderIndexer func(obj *v3.SamlProvider) ([]string, error)

type samlProviderController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewSamlProviderController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) SamlProviderController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &samlProviderController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromSamlProviderHandlerToHandler(sync SamlProviderHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v3.SamlProvider
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v3.SamlProvider))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *samlProviderController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v3.SamlProvider))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateSamlProviderDeepCopyOnChange(client SamlProviderClient, obj *v3.SamlProvider, handler func(obj *v3.SamlProvider) (*v3.SamlProvider, error)) (*v3.SamlProvider, error) {
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

func (c *samlProviderController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *samlProviderController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *samlProviderController) OnChange(ctx context.Context, name string, sync SamlProviderHandler) {
	c.AddGenericHandler(ctx, name, FromSamlProviderHandlerToHandler(sync))
}

func (c *samlProviderController) OnRemove(ctx context.Context, name string, sync SamlProviderHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromSamlProviderHandlerToHandler(sync)))
}

func (c *samlProviderController) Enqueue(name string) {
	c.controller.Enqueue("", name)
}

func (c *samlProviderController) EnqueueAfter(name string, duration time.Duration) {
	c.controller.EnqueueAfter("", name, duration)
}

func (c *samlProviderController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *samlProviderController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *samlProviderController) Cache() SamlProviderCache {
	return &samlProviderCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *samlProviderController) Create(obj *v3.SamlProvider) (*v3.SamlProvider, error) {
	result := &v3.SamlProvider{}
	return result, c.client.Create(context.TODO(), "", obj, result, metav1.CreateOptions{})
}

func (c *samlProviderController) Update(obj *v3.SamlProvider) (*v3.SamlProvider, error) {
	result := &v3.SamlProvider{}
	return result, c.client.Update(context.TODO(), "", obj, result, metav1.UpdateOptions{})
}

func (c *samlProviderController) Delete(name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), "", name, *options)
}

func (c *samlProviderController) Get(name string, options metav1.GetOptions) (*v3.SamlProvider, error) {
	result := &v3.SamlProvider{}
	return result, c.client.Get(context.TODO(), "", name, result, options)
}

func (c *samlProviderController) List(opts metav1.ListOptions) (*v3.SamlProviderList, error) {
	result := &v3.SamlProviderList{}
	return result, c.client.List(context.TODO(), "", result, opts)
}

func (c *samlProviderController) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), "", opts)
}

func (c *samlProviderController) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (*v3.SamlProvider, error) {
	result := &v3.SamlProvider{}
	return result, c.client.Patch(context.TODO(), "", name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type samlProviderCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *samlProviderCache) Get(name string) (*v3.SamlProvider, error) {
	obj, exists, err := c.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v3.SamlProvider), nil
}

func (c *samlProviderCache) List(selector labels.Selector) (ret []*v3.SamlProvider, err error) {

	err = cache.ListAll(c.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v3.SamlProvider))
	})

	return ret, err
}

func (c *samlProviderCache) AddIndexer(indexName string, indexer SamlProviderIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v3.SamlProvider))
		},
	}))
}

func (c *samlProviderCache) GetByIndex(indexName, key string) (result []*v3.SamlProvider, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v3.SamlProvider, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v3.SamlProvider))
	}
	return result, nil
}
