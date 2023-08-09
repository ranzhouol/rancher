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

type proxyContext struct {
	Context  *config.ScaledContext
	Project  *harborproject.Project
	UserInfo *userInfo
}

type userInfo struct {
	authUsername string
	authPassword string
}

func NewHarborProxy(context *config.ScaledContext) *httputil.ReverseProxy {
	pc := &proxyContext{
		Context: context,
	}

	targetUrl, err := url.Parse(pkg.HarborHost)
	if err != nil {
		return nil
	}
	proxy := httputil.NewSingleHostReverseProxy(targetUrl)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		pc.modifyRequest(req)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	proxy.Transport = tr
	proxy.ErrorHandler = errorHandler()

	proxy.ModifyResponse = pc.modifyResponse

	return proxy
}

func errorHandler() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		logrus.Infof("Got error while modifying response: %v \n", err)
		return
	}
}

func (p *proxyContext) modifyRequest(req *http.Request) {
	//userid := req.Header.Get("Impersonate-User")
	//Username := req.Header.Get("Impersonate-Extra-Username")
	context := p.Context
	authUsername, authPassword, err := getUserInfo(context, req)
	p.UserInfo = &userInfo{
		authUsername: authUsername,
		authPassword: authPassword,
	}
	if err != nil {
		logrus.Errorf("制品库获取用户信息失败: %v", err.Error())
	}

	logrus.Info("harbor username: ", authUsername)
	logrus.Info("harbor password: ", authPassword)
	logrus.Info("req:\n", req)
	logrus.Infof("req.RequestURI =%s\n", req.RequestURI)
	logrus.Infof("req.Method =%s\n", req.Method)

	// 创建 harbor 项目
	if req.Method == "POST" && req.RequestURI == "/harbor/api/v2.0/projects" {
		// 使用 project-owner用户创建harbor项目
		if err := p.createHarborProjectModifyHeader(req); err != nil {
			logrus.Errorf("创建制品库requset设置有误: %v", err.Error())
		}
		//logrus.Info("req:\n", req)
		return
	}

	client.RequestSetHeader(authUsername, authPassword, req)
}

func (p *proxyContext) modifyResponse(resp *http.Response) error {
	logrus.Info("resp.Request.Method: ", resp.Request.Method)
	logrus.Info("resp.Request.URL.Path: ", resp.Request.URL.Path)
	if resp.Request.Method == "POST" && resp.Request.URL.Path == "/api/v2.0/projects" {
		//logrus.Info("创建prject response:", resp)
		//if resp.StatusCode == http.StatusCreated { //创建制品库成功
		if err := syncProjectUserToHarbor(p, resp); err != nil {
			logrus.Errorf("制品库用户同步失败:%v", err.Error())
		}
	}
	//}
	return nil
}

// 使用 project-owner用户创建harbor项目
func (p *proxyContext) createHarborProjectModifyHeader(req *http.Request) error {
	body, err := ioutil.ReadAll(req.Body)

	if err != nil {
		logrus.Error("读取响应内容失败:", err)
		return err
	}

	var project *harborproject.Project
	if err := json.Unmarshal(body, &project); err != nil {
		logrus.Error("解析JSON失败: ", err.Error())
		return err
	}
	logrus.Info(project.ProjectEdgesphereName)
	p.Project = project

	projectOwnerName := project.ProjectEdgesphereName + pkg.ProjectOwnerSuffix
	projectOwnerPassword := pkg.MD5String(projectOwnerName)
	client.RequestSetHeader(projectOwnerName, projectOwnerPassword, req)

	req.ContentLength = int64(len(body))
	req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	return nil
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

// 同步项目下的用户到harbor
func syncProjectUserToHarbor(p *proxyContext, resp *http.Response) error {
	logrus.Info("项目名:", p.Project.ProjectEdgesphereName)
	logrus.Info("p.Project.ProjectEdgesphereId:", p.Project.ProjectEdgesphereId)
	//p.Context.Management.Projects("").Get()

	prtblist, err := p.Context.Management.ProjectRoleTemplateBindings(p.Project.ProjectEdgesphereId).List(v1.ListOptions{})
	if err != nil {
		return err
	}

	for _, prtb := range prtblist.Items {
		if prtb.Name == "creator-project-owner" {
			logrus.Info("creator-project-owner名字: ", prtb.Name)
			continue
		}

		userid := prtb.UserName
		user, err := p.Context.Management.Users("").Get(userid, v1.GetOptions{})
		if err != nil {
			logrus.Errorf("failed to get user: %v, err: %v", userid, err.Error())
			return err
		}

		// 创建harbor项目用户
		projectName := p.Project.ProjectName
		username := user.Username
		// user.Description 对应于 authorityLeve
		//displayInt64, _ := strconv.ParseInt(user.Description, 10, 64)
		//roleId := harborproject.AuthorityLeveToRoleId[displayInt64]
		roleId := harborproject.RoleTemplateNameToRoleId[prtb.RoleTemplateName]
		logrus.Info("projectName:", projectName)
		logrus.Info("username:", username)
		logrus.Info("roleID:", roleId)
		if err := harborproject.CreateProjectMember(p.UserInfo.authUsername, p.UserInfo.authPassword, projectName, username, roleId); err != nil {
			if strings.Contains(err.Error(), "The project member specified already exist") {
				if roleId == 1 {
					if err := harborproject.UpdateProjectMember(p.UserInfo.authUsername, p.UserInfo.authPassword, projectName, username, roleId); err != nil {
						logrus.Errorf("更新制品库成员%v失败:%v", username, err.Error())
					}
				}
				continue
			}
			logrus.Errorf("创建制品库成员%v失败:%v", username, err.Error())
			return err
		}
	}

	logrus.Info("制品库用户同步成功")

	return nil
}
