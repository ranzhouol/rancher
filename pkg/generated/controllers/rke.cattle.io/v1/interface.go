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

package v1

import (
	"github.com/rancher/lasso/pkg/controller"
	v1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/wrangler/pkg/schemes"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func init() {
	schemes.Register(v1.AddToScheme)
}

type Interface interface {
	CustomMachine() CustomMachineController
	RKEBootstrap() RKEBootstrapController
	RKEBootstrapTemplate() RKEBootstrapTemplateController
	RKECluster() RKEClusterController
	RKEControlPlane() RKEControlPlaneController
}

func New(controllerFactory controller.SharedControllerFactory) Interface {
	return &version{
		controllerFactory: controllerFactory,
	}
}

type version struct {
	controllerFactory controller.SharedControllerFactory
}

func (c *version) CustomMachine() CustomMachineController {
	return NewCustomMachineController(schema.GroupVersionKind{Group: "rke.cattle.io", Version: "v1", Kind: "CustomMachine"}, "custommachines", true, c.controllerFactory)
}
func (c *version) RKEBootstrap() RKEBootstrapController {
	return NewRKEBootstrapController(schema.GroupVersionKind{Group: "rke.cattle.io", Version: "v1", Kind: "RKEBootstrap"}, "rkebootstraps", true, c.controllerFactory)
}
func (c *version) RKEBootstrapTemplate() RKEBootstrapTemplateController {
	return NewRKEBootstrapTemplateController(schema.GroupVersionKind{Group: "rke.cattle.io", Version: "v1", Kind: "RKEBootstrapTemplate"}, "rkebootstraptemplates", true, c.controllerFactory)
}
func (c *version) RKECluster() RKEClusterController {
	return NewRKEClusterController(schema.GroupVersionKind{Group: "rke.cattle.io", Version: "v1", Kind: "RKECluster"}, "rkeclusters", true, c.controllerFactory)
}
func (c *version) RKEControlPlane() RKEControlPlaneController {
	return NewRKEControlPlaneController(schema.GroupVersionKind{Group: "rke.cattle.io", Version: "v1", Kind: "RKEControlPlane"}, "rkecontrolplanes", true, c.controllerFactory)
}
