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
// +groupName=catalog.cattle.io
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AppList is a list of App resources
type AppList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []App `json:"items"`
}

func NewApp(namespace, name string, obj App) *App {
	obj.APIVersion, obj.Kind = SchemeGroupVersion.WithKind("App").ToAPIVersionAndKind()
	obj.Name = name
	obj.Namespace = namespace
	return &obj
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterRepoList is a list of ClusterRepo resources
type ClusterRepoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterRepo `json:"items"`
}

func NewClusterRepo(namespace, name string, obj ClusterRepo) *ClusterRepo {
	obj.APIVersion, obj.Kind = SchemeGroupVersion.WithKind("ClusterRepo").ToAPIVersionAndKind()
	obj.Name = name
	obj.Namespace = namespace
	return &obj
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OperationList is a list of Operation resources
type OperationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Operation `json:"items"`
}

func NewOperation(namespace, name string, obj Operation) *Operation {
	obj.APIVersion, obj.Kind = SchemeGroupVersion.WithKind("Operation").ToAPIVersionAndKind()
	obj.Name = name
	obj.Namespace = namespace
	return &obj
}
