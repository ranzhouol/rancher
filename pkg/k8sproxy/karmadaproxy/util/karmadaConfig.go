package util

import (
	"context"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func GetKarmadaConfig(client kubernetes.Interface) (*rest.Config, error) {
	//get secret
	karmadaSecret, err := client.CoreV1().Secrets("karmada-system").Get(context.TODO(), "karmada-kubeconfig", metav1.GetOptions{})
	if err != nil {
		karmadaSecret, err = client.CoreV1().Secrets("karmada-system").Get(context.TODO(), "kubeconfig", metav1.GetOptions{})
		if err != nil {
			logrus.Errorf("karmadaSecret err")
			return nil, err
		}
	}
	//get karmadarestconfig
	karmadaConfig, err := clientcmd.RESTConfigFromKubeConfig(karmadaSecret.Data["kubeconfig"])
	if err != nil {
		return nil, err
	}
	return karmadaConfig, nil
}
