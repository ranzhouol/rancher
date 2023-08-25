package project

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg"
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg/client"
	"github.com/sirupsen/logrus"
)

type Quota struct {
	Id   int   `json:"id"`
	Ref  *ref  `json:"ref"`
	Hard *hard `json:"hard"`
	Used *used `json:"used"`
}

type ref struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

type hard struct {
	Storage int64 `json:"storage"`
}

type used struct {
	Storage int64 `json:"storage"`
}

// 更新项目配额
func UpdateProjectQuota(authUsername, authPassword, projectName string, storageLimit int64) error {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	// 获取项目id
	p, err := GetProject(authUsername, authPassword, projectName)
	if err != nil {
		return err
	}

	// 获取配额id
	url := fmt.Sprintf("/api/v2.0/quotas?reference=project&reference_id=%v", p.ProjectId)
	body, err := client.GetClient(authUsername, authPassword, url)
	if err != nil {
		return err
	}

	var quota []*Quota
	if err := json.Unmarshal(body, &quota); err != nil {
		logrus.Error("解析JSON失败: ", err.Error())
		return err
	}

	if len(quota) != 1 {
		return errors.New("修改配额的项目数量不为1")
	}

	// 更新配额
	url2 := fmt.Sprintf("/api/v2.0/quotas/%v", quota[0].Id)
	data := &Quota{
		Hard: &hard{
			Storage: storageLimit,
		},
	}
	err = client.PutClient(authUsername, authPassword, url2, data)
	if err != nil {
		return err
	}

	return nil
}
