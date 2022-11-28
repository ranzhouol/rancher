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

type GithubProviderHandler func(string, *v3.GithubProvider) (*v3.GithubProvider, error)

type GithubProviderController interface {
	generic.ControllerMeta
	GithubProviderClient

	OnChange(ctx context.Context, name string, sync GithubProviderHandler)
	OnRemove(ctx context.Context, name string, sync GithubProviderHandler)
	Enqueue(name string)
	EnqueueAfter(name string, duration time.Duration)

	Cache() GithubProviderCache
}

type GithubProviderClient interface {
	Create(*v3.GithubProvider) (*v3.GithubProvider, error)
	Update(*v3.GithubProvider) (*v3.GithubProvider, error)

	Delete(name string, options *metav1.DeleteOptions) error
	Get(name string, options metav1.GetOptions) (*v3.GithubProvider, error)
	List(opts metav1.ListOptions) (*v3.GithubProviderList, error)
	Watch(opts metav1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v3.GithubProvider, err error)
}

type GithubProviderCache interface {
	Get(name string) (*v3.GithubProvider, error)
	List(selector labels.Selector) ([]*v3.GithubProvider, error)

	AddIndexer(indexName string, indexer GithubProviderIndexer)
	GetByIndex(indexName, key string) ([]*v3.GithubProvider, error)
}

type GithubProviderIndexer func(obj *v3.GithubProvider) ([]string, error)

type githubProviderController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewGithubProviderController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) GithubProviderController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &githubProviderController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromGithubProviderHandlerToHandler(sync GithubProviderHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v3.GithubProvider
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v3.GithubProvider))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *githubProviderController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v3.GithubProvider))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateGithubProviderDeepCopyOnChange(client GithubProviderClient, obj *v3.GithubProvider, handler func(obj *v3.GithubProvider) (*v3.GithubProvider, error)) (*v3.GithubProvider, error) {
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

func (c *githubProviderController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *githubProviderController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *githubProviderController) OnChange(ctx context.Context, name string, sync GithubProviderHandler) {
	c.AddGenericHandler(ctx, name, FromGithubProviderHandlerToHandler(sync))
}

func (c *githubProviderController) OnRemove(ctx context.Context, name string, sync GithubProviderHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromGithubProviderHandlerToHandler(sync)))
}

func (c *githubProviderController) Enqueue(name string) {
	c.controller.Enqueue("", name)
}

func (c *githubProviderController) EnqueueAfter(name string, duration time.Duration) {
	c.controller.EnqueueAfter("", name, duration)
}

func (c *githubProviderController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *githubProviderController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *githubProviderController) Cache() GithubProviderCache {
	return &githubProviderCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *githubProviderController) Create(obj *v3.GithubProvider) (*v3.GithubProvider, error) {
	result := &v3.GithubProvider{}
	return result, c.client.Create(context.TODO(), "", obj, result, metav1.CreateOptions{})
}

func (c *githubProviderController) Update(obj *v3.GithubProvider) (*v3.GithubProvider, error) {
	result := &v3.GithubProvider{}
	return result, c.client.Update(context.TODO(), "", obj, result, metav1.UpdateOptions{})
}

func (c *githubProviderController) Delete(name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), "", name, *options)
}

func (c *githubProviderController) Get(name string, options metav1.GetOptions) (*v3.GithubProvider, error) {
	result := &v3.GithubProvider{}
	return result, c.client.Get(context.TODO(), "", name, result, options)
}

func (c *githubProviderController) List(opts metav1.ListOptions) (*v3.GithubProviderList, error) {
	result := &v3.GithubProviderList{}
	return result, c.client.List(context.TODO(), "", result, opts)
}

func (c *githubProviderController) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), "", opts)
}

func (c *githubProviderController) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (*v3.GithubProvider, error) {
	result := &v3.GithubProvider{}
	return result, c.client.Patch(context.TODO(), "", name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type githubProviderCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *githubProviderCache) Get(name string) (*v3.GithubProvider, error) {
	obj, exists, err := c.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v3.GithubProvider), nil
}

func (c *githubProviderCache) List(selector labels.Selector) (ret []*v3.GithubProvider, err error) {

	err = cache.ListAll(c.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v3.GithubProvider))
	})

	return ret, err
}

func (c *githubProviderCache) AddIndexer(indexName string, indexer GithubProviderIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v3.GithubProvider))
		},
	}))
}

func (c *githubProviderCache) GetByIndex(indexName, key string) (result []*v3.GithubProvider, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v3.GithubProvider, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v3.GithubProvider))
	}
	return result, nil
}
