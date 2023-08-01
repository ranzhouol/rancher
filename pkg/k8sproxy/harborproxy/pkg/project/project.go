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

// 项目成员
type ProjectMember struct {
	RoleId     int         `json:"role_id"`
	MemberUser *memberUser `json:"member_user"`
}

type memberUser struct {
	Username string `json:"username"`
}

func GetProject(authUsername, authPassword, projectNameOrid string) (*Project, error) {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	url := fmt.Sprintf("/api/v2.0/projects/%v", projectNameOrid)
	body, err := client.GetClient(authUsername, authPassword, url)
	if err != nil {
		return nil, err
	}

	var p Project
	if err := json.Unmarshal(body, &p); err != nil {
		logrus.Error("解析JSON失败: ", err.Error())
		return nil, err
	}

	return &p, nil
}

func Create(authUsername, authPassword, projectName, public string, storageLimit int64) error {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	projectName = strings.ToLower(projectName)
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
