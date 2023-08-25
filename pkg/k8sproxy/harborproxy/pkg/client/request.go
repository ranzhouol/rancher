package client

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/rancher/rancher/pkg/k8sproxy/harborproxy/pkg"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strings"
)

func RequestSetHeader(username, password string, req *http.Request) {
	auth := username + ":" + password
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	logrus.Info("req.header1: ", req.Header)
	req.Header.Del("Cookie")
	req.Header.Set("Access-Control-Allow-Origin", "*")
	req.Header.Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, OPTIONS")
	req.Header.Set("Authorization", basicAuth)
	if strings.Contains(req.URL.Path, "/api/chartrepo/") && req.Method == "POST" {
		req.Header.Set("accept", "*/*")
		return
	}

	// 下载ca证书
	if strings.Contains(req.URL.Path, "/api/v2.0/systeminfo/getcert") && req.Method == "GET" {
		req.Header.Set("accept", "application/octet-stream")
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("accept", "application/json")
	logrus.Info("req.header2: ", req.Header)
}

func GetClient(username, password, urlPath string) ([]byte, error) {
	// 创建HTTP客户端并跳过证书验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// 创建GET请求
	req, err := http.NewRequest("GET", pkg.HarborHost+urlPath, nil)
	if err != nil {
		//logrus.Error("Create request error: ", err)
		return nil, err
	}

	RequestSetHeader(username, password, req)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		//logrus.Error("Request error: ", err)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		//logrus.Error("读取响应内容失败:", err)
		return nil, err
	}

	// 查看结果
	if resp.StatusCode != http.StatusOK {
		logrus.Info("GET失败, 状态码: ", resp.StatusCode)
		return nil, errors.New(string(body))
	}

	return body, nil
}

func PutClient(username, password, urlPath string, data interface{}) error {
	// 创建HTTP客户端并跳过证书验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	dataByte, err := json.Marshal(data)
	if err != nil {
		//logrus.Error("Data JSON encoding err: ", err.Error())
		return err
	}

	// 创建PUT请求
	req, err := http.NewRequest("PUT", pkg.HarborHost+urlPath, bytes.NewBuffer(dataByte))
	if err != nil {
		//logrus.Error("Create request error: ", err)
		return err
	}

	RequestSetHeader(username, password, req)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		//logrus.Error("Request error: ", err)
		return err
	}
	defer resp.Body.Close()

	// 查看结果
	if resp.StatusCode == http.StatusOK {
		//logrus.Info("PUT成功")
		return nil
	} else {
		logrus.Info("PUT失败, 状态码: ", resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			//logrus.Error("读取响应内容失败:", err)
			return err
		}
		//logrus.Info(string(body))
		return errors.New(string(body))
	}
}

func PostClient(username, password, urlPath string, data interface{}) error {
	// 创建HTTP客户端并跳过证书验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	dataByte, err := json.Marshal(data)
	if err != nil {
		//logrus.Error("Data JSON encoding err: ", err.Error())
		return err
	}

	// 创建POST请求
	req, err := http.NewRequest("POST", pkg.HarborHost+urlPath, bytes.NewBuffer(dataByte))
	if err != nil {
		//logrus.Error("Create request error: ", err)
		return err
	}

	RequestSetHeader(username, password, req)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		//logrus.Error("Request error: ", err)
		return err
	}
	defer resp.Body.Close()

	// 查看结果
	if resp.StatusCode == http.StatusCreated {
		//logrus.Info("POST成功")
		return nil
	} else {
		logrus.Info("POST失败, 状态码: ", resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			//logrus.Error("读取响应内容失败:", err)
			return err
		}
		//logrus.Info(string(body))
		return errors.New(string(body))
	}
}

func DeleteClient(username, password, urlPath string) error {
	// 创建HTTP客户端并跳过证书验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// 创建DELETE请求
	req, err := http.NewRequest("DELETE", pkg.HarborHost+urlPath, nil)
	if err != nil {
		//logrus.Error("Create request error: ", err)
		return err
	}

	RequestSetHeader(username, password, req)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		//logrus.Error("Request error: ", err)
		return err
	}
	defer resp.Body.Close()

	// 查看结果
	if resp.StatusCode == http.StatusOK {
		//logrus.Info("DELETE成功")
		return nil
	} else {
		logrus.Info("DELETE失败, 状态码: ", resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			//logrus.Error("读取响应内容失败:", err)
			return err
		}
		//logrus.Info(string(body))
		return errors.New(string(body))
	}
}
