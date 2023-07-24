package user

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg"
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg/client"
	"github.com/sirupsen/logrus"
)

type User struct {
	Username     string `json:"username"`
	UserId       int    `json:"user_id"`
	Password     string `json:"password"`
	NewPassword  string `json:"new_password"`
	Email        string `json:"email"`
	Realname     string `json:"realname"`
	Comment      string `json:"comment"`
	SysadminFlag bool   `json:"sysadmin_flag"`
}

func GetAllUser() ([]User, error) {
	url := "/api/v2.0/users"
	body, err := client.GetClient(pkg.HarborAdminUsername, pkg.HarborAdminPassword, url)
	if err != nil {
		return nil, err
	}

	var users []User
	if err := json.Unmarshal(body, &users); err != nil {
		logrus.Error("解析JSON失败: ", err.Error())
		return nil, err
	}

	return users, nil
}

func GetUserId(username string) (int, error) {
	users, err := GetAllUser()
	if err != nil {
		return -1, err
	}

	for _, u := range users {
		if u.Username == username {
			return u.UserId, nil
		}
	}
	notFind := fmt.Sprintf("制品库不存在该用户:%v", username)
	return -1, errors.New(notFind)
}

func Create(username, password, email, realname string) error {
	user := &User{
		Username: username,
		Password: password,
		Email:    email,
		Realname: realname,
	}
	url := "/api/v2.0/users"
	err := client.PostClient(pkg.HarborAdminUsername, pkg.HarborAdminPassword, url, user)
	if err != nil {
		return err
	}
	return nil
}

func Delete(userid int) error {
	url := fmt.Sprintf("/api/v2.0/users/%v", userid)
	err := client.DeleteClient(pkg.HarborAdminUsername, pkg.HarborAdminPassword, url)
	if err != nil {
		return err
	}
	return nil
}

func ChangePassword(username, newPassword string) error {
	// 获取用户id
	userid, err := GetUserId(username)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("/api/v2.0/users/%v/password", userid)
	data := &User{
		NewPassword: newPassword,
	}
	err = client.PutClient(pkg.HarborAdminUsername, pkg.HarborAdminPassword, url, data)
	if err != nil {
		return err
	}

	return nil
}

// 设置管理员用户
func SetAdmin(username string, isAdmin bool) error {
	// 获取用户id
	userid, err := GetUserId(username)
	if err != nil {
		return err
	}

	data := &User{
		SysadminFlag: isAdmin,
	}
	url := fmt.Sprintf("/api/v2.0/users/%v/sysadmin", userid)

	err = client.PutClient(pkg.HarborAdminUsername, pkg.HarborAdminPassword, url, data)
	if err != nil {
		return err
	}

	return nil
}
