package harborproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg"
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg/client"
	harborproject "github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg/project"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func NewHarborProxy(context *config.ScaledContext) *httputil.ReverseProxy {
	targetUrl, err := url.Parse(pkg.HarborHost)
	if err != nil {
		return nil
	}
	proxy := httputil.NewSingleHostReverseProxy(targetUrl)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		modifyRequest(context, req)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	proxy.Transport = tr
	proxy.ErrorHandler = errorHandler()

	return proxy
}

func errorHandler() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		logrus.Infof("Got error while modifying response: %v \n", err)
		return
	}
}

func modifyRequest(context *config.ScaledContext, req *http.Request) {
	//userid := req.Header.Get("Impersonate-User")
	//harborUsername := req.Header.Get("Impersonate-Extra-Username")
	authUsername, authPassword, err := getUserInfo(context, req)
	if err != nil {
		logrus.Errorf("制品库获取用户信息失败: %v", err.Error())
	}

	logrus.Info("harbor username: ", authUsername)
	logrus.Info("harbor password: ", authPassword)
	logrus.Info("req:\n", req)
	logrus.Infof("req.RequestURI =%s\n", req.RequestURI)
	logrus.Infof("req.Method =%s\n", req.Method)

	if req.Method == "POST" && req.RequestURI == "/harbor/api/v2.0/projects" {
		// 使用 project-owner用户创建harbor项目
		if err := createHarborProjectModifyHeader(req); err != nil {
			logrus.Errorf("创建制品库requset设置有误: %v", err.Error())
		}
		logrus.Info("req:\n", req)
		return
	}

	client.RequestSetHeader(authUsername, authPassword, req)
}

// 获取用户名、密码
func getUserInfo(context *config.ScaledContext, req *http.Request) (string, string, error) {
	userid := req.Header.Get("Impersonate-User")
	if len(userid) == 0 {
		return "", "", errors.New("No user found")
	}

	authUser, err := context.Wrangler.Mgmt.User().Get(userid, v1.GetOptions{})
	if err != nil {
		return "", "", err
	}

	authUsername := authUser.Username
	if authUsername == "admin" {
		return authUsername, pkg.HarborAdminPassword, nil
	}

	encryptAuthPassword := authUser.EdgespherePW
	if len(encryptAuthPassword) == 0 { //初次登录
		return authUsername, "", errors.New("EdgespherePW does not exist")
	}

	// 解码
	authPassword, err := pkg.DecryptString(pkg.Key, encryptAuthPassword)
	if err != nil {
		logrus.Errorf("解码失败: %v", err.Error())
		return authUsername, "", err
	}

	return authUsername, authPassword, nil
}

func ProxyRequestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// 去除url中的多余前缀
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/harbor")

		proxy.ServeHTTP(w, r)
	}
}

// 使用 project-owner用户创建harbor项目
func createHarborProjectModifyHeader(req *http.Request) error {
	body, err := ioutil.ReadAll(req.Body)

	if err != nil {
		logrus.Error("读取响应内容失败:", err)
		return err
	}

	var project harborproject.Project
	if err := json.Unmarshal(body, &project); err != nil {
		logrus.Error("解析JSON失败: ", err.Error())
		return err
	}
	logrus.Info(project.ProjectEdgesphereName)

	projectOwnerName := project.ProjectEdgesphereName + pkg.ProjectOwnerSuffix
	projectOwnerPassword := pkg.MD5String(projectOwnerName)
	client.RequestSetHeader(projectOwnerName, projectOwnerPassword, req)

	req.ContentLength = int64(len(body))
	req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	return nil
}
