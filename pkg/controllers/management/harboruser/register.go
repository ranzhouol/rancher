package harboruser

import (
	"context"
	apis "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	harboruser "github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg/user"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
)

/*
	rz：弃用
*/
const (
	harborUserController = "harbor-users"
)

type HarborUserHandler struct {
	Manager *config.ManagementContext
	ctx     context.Context
}

func Register(ctx context.Context, management *config.ManagementContext) {
	h := &HarborUserHandler{
		Manager: management,
		ctx:     ctx,
	}

	management.Management.Users("").AddHandler(ctx, harborUserController, h.sync)
}

func (h HarborUserHandler) sync(key string, obj *apis.User) (runtime.Object, error) {
	if obj == nil || len(obj.Username) == 0 || len(obj.Password) == 0 {
		return obj, nil
	}

	if obj.DeletionTimestamp == nil {
		//create
		if value, ok := obj.GetAnnotations()[harborUserController]; (!ok || value != "true") && obj.Username != "admin" {
			//logrus.Info("useranno: ", obj.Annotations)
			//err := h.Create(obj.Username, obj.Password, obj.Email, obj.DisplayName)
			err := h.Create(obj.Username, obj.Password, obj.Username+"@qq.com", obj.Username)
			if err != nil {
				logrus.Errorf("创建 harbor 用户 %s 失败:%s", obj.Username, err.Error())
				return obj, nil
			} else {
				logrus.Infof("创建 harbor 用户 %s 成功", obj.Username)
				obj.Annotations[harborUserController] = "true"
				logrus.Info("useranno: ", obj.Annotations)
				h.Manager.Management.Users("").Update(obj)
			}
		}
	} else {
		//delete
	}

	return obj, nil
}

func (h HarborUserHandler) Create(username, password, email, realname string) error {
	logrus.Infof("username:%s,password:%s,email:%s,displayname:%s", username, password, email, realname)
	err := harboruser.Create(username, password, email, realname)
	if err != nil {
		return err
	}
	return nil
}
