package requests

import (
	"net/http"
	"strings"

	"github.com/rancher/rancher/pkg/auth/audit"
	"github.com/rancher/rancher/pkg/auth/providers"
	"github.com/rancher/rancher/pkg/auth/util"
	"github.com/sirupsen/logrus"
	"k8s.io/apiserver/pkg/endpoints/request"
)

//认证过滤器
func NewAuthenticatedFilter(next http.Handler) http.Handler {
	return &authHeaderHandler{
		next: next,
	}
}

type authHeaderHandler struct {
	next http.Handler
}

func (h authHeaderHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	//1、获取用户信息，认证标识
	userInfo, authed := request.UserFrom(req.Context())
	// checking for system:cattle:error user keeps the old behavior of always returning 401 when authentication fails
	if !authed || userInfo.GetName() == "system:cattle:error" {
		util.ReturnHTTPError(rw, req, 401, ErrMustAuthenticate.Error())
		return
	}

	//clean extra that is not part of userInfo
	//
	for header := range req.Header {
		if strings.HasPrefix(header, "Impersonate-Extra-") {
			key := strings.TrimPrefix(header, "Impersonate-Extra-")
			if !providers.IsValidUserExtraAttribute(key) {
				req.Header.Del(header)
			}
		}
	}

	req.Header.Set("Impersonate-User", userInfo.GetName())
	req.Header.Del("Impersonate-Group")
	for _, group := range userInfo.GetGroups() {
		req.Header.Add("Impersonate-Group", group)
	}

	for key, extras := range userInfo.GetExtra() {
		for _, s := range extras {
			if s != "" {
				req.Header.Add("Impersonate-Extra-"+key, s)
			}
		}
	}

	logrus.Tracef("Rancher Auth Filter ##headers %v: ", req.Header)

	auditUser, ok := audit.FromContext(req.Context())
	if ok {
		auditUser.Name = userInfo.GetName()
		auditUser.Group = userInfo.GetGroups()
	}

	h.next.ServeHTTP(rw, req)
}

//带条件的认证过滤器
func NewRequireAuthenticatedFilter(pathPrefix string, ignorePrefix ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &authedFilter{
			next:         next,
			pathPrefix:   pathPrefix,
			ignorePrefix: ignorePrefix,
		}
	}
}

type authedFilter struct {
	next         http.Handler
	pathPrefix   string
	ignorePrefix []string
}

//验证是否是需要认证的path
func (h authedFilter) matches(path string) bool {
	if strings.HasPrefix(path, h.pathPrefix) {
		for _, prefix := range h.ignorePrefix {
			if strings.HasPrefix(path, prefix) {
				return false
			}
		}
		return true
	}
	return false
}

func (h authedFilter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if h.matches(req.URL.Path) {
		// 1、获取用户信息，授权标识
		userInfo, authed := request.UserFrom(req.Context())
		// checking for system:cattle:error user keeps the old behavior of always returning 401 when authentication fails
		if !authed || userInfo.GetName() == "system:cattle:error" {
			util.ReturnHTTPError(rw, req, 401, ErrMustAuthenticate.Error())
			return
		}
	}

	h.next.ServeHTTP(rw, req)
}
