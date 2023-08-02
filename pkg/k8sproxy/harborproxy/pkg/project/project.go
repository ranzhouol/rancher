package project

import (
	"encoding/json"
	"fmt"
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg"
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg/client"
	"github.com/sirupsen/logrus"
	"strings"
)

// edgesphere用户与harbor项目成员的对应关系
var AuthorityLeveToRoleId = map[int64]int{
	2: 1,
	3: 2,
}

// 创建项目时使用
type Project struct {
	ProjectName  string    `json:"project_name"`
	MetaData     *metadata `json:"metadata"`
	StorageLimit int64     `json:"storage_limit"`
	RegistryId   int64     `json:"registry_id,omitempty"`
	// add
	ProjectEdgesphereName string `json:"project_edgesphere_name,omitempty"`
	ProjectEdgesphereId   string `json:"project_edgesphere_id,omitempty"`
}

type metadata struct {
	Public string `json:"public"`
}

// 响应的项目结构体
type ResponseProject struct {
	Name       string `json:"name"`
	ProjectId  int32  `json:"project_id"`
	OwnerName  string `json:"owner_name"`
	OwnerId    int32  `json:"owner_id"`
	RepoCount  int    `json:"repo_count"`
	ChartCount int    `json:"chart_count"`
}

// 项目成员
type ProjectMember struct {
	RoleId     int         `json:"role_id"`
	MemberUser *memberUser `json:"member_user"`
}

type memberUser struct {
	Username string `json:"username"`
}

// 项目可删除状态
type ProjectDeletable struct {
	Message   string `json:"message"`
	Deletable bool   `json:"deletable"`
}

func GetProject(authUsername, authPassword, projectNameOrid string) (*ResponseProject, error) {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	url := fmt.Sprintf("/api/v2.0/projects/%v", projectNameOrid)
	body, err := client.GetClient(authUsername, authPassword, url)
	if err != nil {
		return nil, err
	}

	var p *ResponseProject
	if err := json.Unmarshal(body, &p); err != nil {
		logrus.Error("解析JSON失败: ", err.Error())
		return nil, err
	}

	return p, nil
}

func Create(authUsername, authPassword, projectName, public string, storageLimit int64) error {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	projectName = strings.ToLower(projectName) // 用于Default和System项目
	m := &metadata{
		Public: public,
	}

	project := &Project{
		ProjectName:  projectName,
		MetaData:     m,
		StorageLimit: storageLimit,
	}

	url := "/api/v2.0/projects"
	err := client.PostClient(authUsername, authPassword, url, project)
	if err != nil {
		return err
	}

	return nil
}

// 创建harbor项目成员
func CreateProjectMember(authUsername, authPassword, projectName, username string, roleId int) error {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	member := &memberUser{
		Username: username,
	}

	projectMember := &ProjectMember{
		RoleId:     roleId,
		MemberUser: member,
	}

	url := fmt.Sprintf("/api/v2.0/projects/%v/members", projectName)
	err := client.PostClient(authUsername, authPassword, url, projectMember)
	if err != nil {
		return err
	}

	return nil
}

// 查看项目的可删除状态
func GetProjectDeletable(authUsername, authPassword, projectNameOrId string) (bool, error) {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	url := fmt.Sprintf("/api/v2.0/projects/%v/_deletable", projectNameOrId)
	body, err := client.GetClient(authUsername, authPassword, url)
	if err != nil {
		return false, err
	}

	var projectDeletable *ProjectDeletable
	if err := json.Unmarshal(body, &projectDeletable); err != nil {
		logrus.Error("解析JSON失败: ", err.Error())
		return false, err
	}

	if projectDeletable.Deletable == true {
		return true, nil
	}

	return false, nil
}

// 获取用户创建的所有项目
func GetAllPeojectCreatedByUser(authUsername, authPassword, username string) ([]*ResponseProject, error) {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	url := fmt.Sprintf("/api/v2.0/projects?owner=%v&page=1&page_size=-1", username)
	body, err := client.GetClient(authUsername, authPassword, url)
	if err != nil {
		return nil, err
	}

	var projects []*ResponseProject
	if err := json.Unmarshal(body, &projects); err != nil {
		logrus.Error("解析JSON失败: ", err.Error())
		return nil, err
	}

	return projects, nil
}

func Delete(authUsername, authPassword, projectNameOrId string) error {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	url := fmt.Sprintf("/api/v2.0/projects/%v", projectNameOrId)
	err := client.DeleteClient(authUsername, authPassword, url)
	if err != nil {
		return err
	}

	return nil
}
