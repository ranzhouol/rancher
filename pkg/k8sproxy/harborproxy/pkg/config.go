package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

const (
	HarborHost = "https://ranzhou.harbor.com"
	//HarborHost = "https://harbor-core.harbor.svc.cluster.local:443"

	// harbor admin
	HarborAdminUsername = "admin"
	//HarborAdminPassword   = "Harbor12345"
	HarborEdgesphereAdmin         = "admin-edgesphere"
	HarborEdgesphereAdminPassword = "Harbor12345"

	// 密钥
	Key = "szsciit-Edgesphere-123$%" // 24 字节的密钥

	// project 用户名后缀
	ProjectOwnerSuffix     = "-owner"
	ProjectOwnerAnnotation = "edgesphere-registry-owner"

	// project-helmchart 项目后缀
	ProjectHelmChartSuffix     = "-helmchart"
	ProjectHelmChartAnnotation = "edgesphere-registry-helmchart"
)

var (
	HarborAdminPassword, HarborNamespace = GetHarborInfo()

	//HarborHost = fmt.Sprintf("https://harbor-core.%v.svc.cluster.local:443", HarborNamespace)
)

// 获取 harbor admin密码和命名空间
func GetHarborInfo() (string, string) {
	adminPassword := os.Getenv("HARBOR_PASSWORD")
	if adminPassword == "" {
		adminPassword = "Harbor12345"
	}

	harborNamespace := os.Getenv("HARBOR_NAMESPACE")
	if harborNamespace == "" {
		harborNamespace = "harbor"
	}

	return adminPassword, harborNamespace
}

// 加密
func EncryptString(key, str string) (string, error) {
	plaintext := []byte(str)

	// 创建 AES 加密块
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// 创建 Galois/Counter Mode (GCM) 进行加密。可以选择其他模式，如 Cipher Block Chaining (CBC)。
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// 生成随机 nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// 使用密钥和随机生成的 nonce 进行加密
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// 将随机数 nonce 与密文连接起来并返回
	encryptedData := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(encryptedData), nil
}

// 解密
func DecryptString(key, encStr string) (string, error) {
	encryptedData, err := base64.StdEncoding.DecodeString(encStr)
	if err != nil {
		return "", err
	}

	// 创建 AES 加密块
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// 创建 Galois/Counter Mode (GCM) 进行解密
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// 提取 nonce 和密文
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return "", fmt.Errorf("invalid ciphertext")
	}
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	// 使用密钥和 nonce 进行解密
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// MD5加密 16位, 并且末尾添加 1aA
func MD5String(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	md5Str := fmt.Sprintf("%x", h.Sum(nil))
	password := md5Str[8:24] + "1aA"
	return password
}
