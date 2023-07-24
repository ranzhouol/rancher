package harborproxy

import (
	"crypto/tls"
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg"
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg/client"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func NewHarborProxy() *httputil.ReverseProxy {
	targetUrl, err := url.Parse(pkg.HarborHost)
	if err != nil {
		return nil
	}
	proxy := httputil.NewSingleHostReverseProxy(targetUrl)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		modifyRequest(req)
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

func modifyRequest(req *http.Request) {
	//userid := req.Header.Get("Impersonate-User")
	harborUsername := req.Header.Get("Impersonate-Extra-Username")
	harborPassword := pkg.HarborAdminPassword
	logrus.Info("harbor username: ", harborUsername)
	logrus.Info("req:\n", req)
	logrus.Infof("req.RequestURI =%s\n", req.RequestURI)
	logrus.Infof("req.Method =%s\n", req.Method)

	client.RequestSetHeader(harborUsername, harborPassword, req)
}
func ProxyRequestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// 去除url中的多余前缀
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/harbor")

		proxy.ServeHTTP(w, r)
	}
}
