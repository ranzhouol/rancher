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

// +k8s:deepcopy-gen=package
// +groupName=cluster.cattle.io
package v3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterAuthTokenList is a list of ClusterAuthToken resources
type ClusterAuthTokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterAuthToken `json:"items"`
}

func NewClusterAuthToken(namespace, name string, obj ClusterAuthToken) *ClusterAuthToken {
	obj.APIVersion, obj.Kind = SchemeGroupVersion.WithKind("ClusterAuthToken").ToAPIVersionAndKind()
	obj.Name = name
	obj.Namespace = namespace
	return &obj
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterUserAttributeList is a list of ClusterUserAttribute resources
type ClusterUserAttributeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterUserAttribute `json:"items"`
}

func NewClusterUserAttribute(namespace, name string, obj ClusterUserAttribute) *ClusterUserAttribute {
	obj.APIVersion, obj.Kind = SchemeGroupVersion.WithKind("ClusterUserAttribute").ToAPIVersionAndKind()
	obj.Name = name
	obj.Namespace = namespace
	return &obj
}
