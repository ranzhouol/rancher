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
	OldPassword  string `json:"old_password"`
	NewPassword  string `json:"new_password"`
	Email        string `json:"email"`
	Realname     string `json:"realname"`
	Comment      string `json:"comment"`
	SysadminFlag bool   `json:"sysadmin_flag"`
}

func GetAllUser(authUsername, authPassword string) ([]User, error) {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	url := "/api/v2.0/users"
	body, err := client.GetClient(authUsername, authPassword, url)
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

// 获取当前用户id
func GetCurrentUserId(authUsername, authPassword string) (int, error) {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	url := "/api/v2.0/users/current"
	body, err := client.GetClient(authUsername, authPassword, url)
	if err != nil {
		return -1, err
	}

	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		logrus.Errorf("解析JSON失败: %v", err.Error())
		return -1, err
	}

	return user.UserId, nil
}

// 获取指定用户名的id
func GetUserId(authUsername, authPassword, username string) (int, error) {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	users, err := GetAllUser(authUsername, authPassword)
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

func Create(authUsername, authPassword, username, password, email, realname, comment string) error {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	user := &User{
		Username: username,
		Password: password,
		Email:    email,
		Realname: realname,
		Comment:  comment,
	}
	url := "/api/v2.0/users"
	err := client.PostClient(authUsername, authPassword, url, user)
	if err != nil {
		return err
	}

	// 判断是否为系统管理员
	if comment == "1" {
		err := SetAdmin(authUsername, authPassword, username, true)
		if err != nil {
			return errors.New(fmt.Sprintf("设置制品库管理员%v失败: %v", username, err.Error()))
		}
	}
	return nil
}

func Delete(authUsername, authPassword, username string) error {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	// 获取用户id
	userid, err := GetUserId(authUsername, authPassword, username)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("/api/v2.0/users/%v", userid)
	err = client.DeleteClient(authUsername, authPassword, url)
	if err != nil {
		return err
	}
	return nil
}

// 修改指定用户名的密码
func ChangePassword(authUsername, authPassword, username, newPassword string) error {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	if username == "admin" {
		username = pkg.HarborEdgesphereAdmin
	}
	// 获取用户id
	userid, err := GetUserId(authUsername, authPassword, username)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("/api/v2.0/users/%v/password", userid)
	data := &User{
		NewPassword: newPassword,
	}
	err = client.PutClient(authUsername, authPassword, url, data)
	if err != nil {
		return err
	}

	return nil
}

// 修改当前用户密码
func ChangeCurrentPassword(authUsername, authPassword, newPassword string) error {
	if authUsername == "admin" {
		authUsername = pkg.HarborEdgesphereAdmin
	}
	// 获取用户id
	userid, err := GetCurrentUserId(authUsername, authPassword)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("/api/v2.0/users/%v/password", userid)
	data := &User{
		NewPassword: newPassword,
		OldPassword: authPassword,
	}
	err = client.PutClient(authUsername, authPassword, url, data)
	if err != nil {
		return err
	}

	return nil
}

// 设置管理员用户
func SetAdmin(authUsername, authPassword, username string, isAdmin bool) error {
	if authUsername == "admin" {
		authPassword = pkg.HarborAdminPassword
	}

	// 获取用户id
	userid, err := GetUserId(authUsername, authPassword, username)
	if err != nil {
		return err
	}

	data := &User{
		SysadminFlag: isAdmin,
	}
	url := fmt.Sprintf("/api/v2.0/users/%v/sysadmin", userid)

	err = client.PutClient(authUsername, authPassword, url, data)
	if err != nil {
		return err
	}

	return nil
}
