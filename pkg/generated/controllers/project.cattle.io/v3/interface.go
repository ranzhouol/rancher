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
	"github.com/rancher/lasso/pkg/controller"
	v3 "github.com/rancher/rancher/pkg/apis/project.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/schemes"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func init() {
	schemes.Register(v3.AddToScheme)
}

type Interface interface {
	App() AppController
	AppRevision() AppRevisionController
	BasicAuth() BasicAuthController
	Certificate() CertificateController
	DockerCredential() DockerCredentialController
	NamespacedBasicAuth() NamespacedBasicAuthController
	NamespacedCertificate() NamespacedCertificateController
	NamespacedDockerCredential() NamespacedDockerCredentialController
	NamespacedSSHAuth() NamespacedSSHAuthController
	NamespacedServiceAccountToken() NamespacedServiceAccountTokenController
	Pipeline() PipelineController
	PipelineExecution() PipelineExecutionController
	PipelineSetting() PipelineSettingController
	SSHAuth() SSHAuthController
	ServiceAccountToken() ServiceAccountTokenController
	SourceCodeCredential() SourceCodeCredentialController
	SourceCodeProvider() SourceCodeProviderController
	SourceCodeProviderConfig() SourceCodeProviderConfigController
	SourceCodeRepository() SourceCodeRepositoryController
	Workload() WorkloadController
}

func New(controllerFactory controller.SharedControllerFactory) Interface {
	return &version{
		controllerFactory: controllerFactory,
	}
}

type version struct {
	controllerFactory controller.SharedControllerFactory
}

func (c *version) App() AppController {
	return NewAppController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "App"}, "apps", true, c.controllerFactory)
}
func (c *version) AppRevision() AppRevisionController {
	return NewAppRevisionController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "AppRevision"}, "apprevisions", true, c.controllerFactory)
}
func (c *version) BasicAuth() BasicAuthController {
	return NewBasicAuthController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "BasicAuth"}, "basicauths", true, c.controllerFactory)
}
func (c *version) Certificate() CertificateController {
	return NewCertificateController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "Certificate"}, "certificates", true, c.controllerFactory)
}
func (c *version) DockerCredential() DockerCredentialController {
	return NewDockerCredentialController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "DockerCredential"}, "dockercredentials", true, c.controllerFactory)
}
func (c *version) NamespacedBasicAuth() NamespacedBasicAuthController {
	return NewNamespacedBasicAuthController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "NamespacedBasicAuth"}, "namespacedbasicauths", true, c.controllerFactory)
}
func (c *version) NamespacedCertificate() NamespacedCertificateController {
	return NewNamespacedCertificateController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "NamespacedCertificate"}, "namespacedcertificates", true, c.controllerFactory)
}
func (c *version) NamespacedDockerCredential() NamespacedDockerCredentialController {
	return NewNamespacedDockerCredentialController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "NamespacedDockerCredential"}, "namespaceddockercredentials", true, c.controllerFactory)
}
func (c *version) NamespacedSSHAuth() NamespacedSSHAuthController {
	return NewNamespacedSSHAuthController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "NamespacedSSHAuth"}, "namespacedsshauths", true, c.controllerFactory)
}
func (c *version) NamespacedServiceAccountToken() NamespacedServiceAccountTokenController {
	return NewNamespacedServiceAccountTokenController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "NamespacedServiceAccountToken"}, "namespacedserviceaccounttokens", true, c.controllerFactory)
}
func (c *version) Pipeline() PipelineController {
	return NewPipelineController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "Pipeline"}, "pipelines", true, c.controllerFactory)
}
func (c *version) PipelineExecution() PipelineExecutionController {
	return NewPipelineExecutionController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "PipelineExecution"}, "pipelineexecutions", true, c.controllerFactory)
}
func (c *version) PipelineSetting() PipelineSettingController {
	return NewPipelineSettingController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "PipelineSetting"}, "pipelinesettings", true, c.controllerFactory)
}
func (c *version) SSHAuth() SSHAuthController {
	return NewSSHAuthController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "SSHAuth"}, "sshauths", true, c.controllerFactory)
}
func (c *version) ServiceAccountToken() ServiceAccountTokenController {
	return NewServiceAccountTokenController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "ServiceAccountToken"}, "serviceaccounttokens", true, c.controllerFactory)
}
func (c *version) SourceCodeCredential() SourceCodeCredentialController {
	return NewSourceCodeCredentialController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "SourceCodeCredential"}, "sourcecodecredentials", true, c.controllerFactory)
}
func (c *version) SourceCodeProvider() SourceCodeProviderController {
	return NewSourceCodeProviderController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "SourceCodeProvider"}, "sourcecodeproviders", false, c.controllerFactory)
}
func (c *version) SourceCodeProviderConfig() SourceCodeProviderConfigController {
	return NewSourceCodeProviderConfigController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "SourceCodeProviderConfig"}, "sourcecodeproviderconfigs", true, c.controllerFactory)
}
func (c *version) SourceCodeRepository() SourceCodeRepositoryController {
	return NewSourceCodeRepositoryController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "SourceCodeRepository"}, "sourcecoderepositories", true, c.controllerFactory)
}
func (c *version) Workload() WorkloadController {
	return NewWorkloadController(schema.GroupVersionKind{Group: "project.cattle.io", Version: "v3", Kind: "Workload"}, "workloads", true, c.controllerFactory)
}
