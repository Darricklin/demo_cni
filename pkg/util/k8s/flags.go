package k8s

import (
	"fmt"
	"github.com/spf13/pflag"
	"strings"
)

type Flags struct {
	K8sApiServer string `json:"k8s_api_server"`
	K8sCA        string `json:"k8s_ca"`
	K8sKey       string `json:"k8s_key"`
	K8sCert      string `json:"k8s_cert"`
	K8sToken     string `json:"k8s_token"`
}

func NewK8sFlags() *Flags {
	return &Flags{
		K8sApiServer: "http://127.0.0.1:8080",
		K8sCA:        "",
		K8sKey:       "",
		K8sCert:      "",
		K8sToken:     "",
	}
}
func (f *Flags) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&f.K8sApiServer, "k8s-api-server", f.K8sApiServer, "The api endpoint of k8s api server")
	fs.StringVar(&f.K8sCA, "k8s-ca", f.K8sCA, "The ca file which trusts the k8s api server")
	fs.StringVar(&f.K8sCert, "k8s-cert", f.K8sCert, "The TLS cert file used to access the k8s api server")
	fs.StringVar(&f.K8sKey, "k8s-key", f.K8sKey, "The TLS key file used to access the k8s api server")
	fs.StringVar(&f.K8sToken, "k8s-token", f.K8sToken, "The bearer token used to access the k8s api server")
}

func (f *Flags) ValidateFlags() error {
	var allErrStrs []string
	if strings.HasPrefix(f.K8sApiServer, "https") {
		if f.K8sCA == "" {
			allErrStrs = append(allErrStrs, "empty k8s ca")
		} else if f.K8sToken == "" && !(f.K8sCert != "" && f.K8sKey != "") {
			allErrStrs = append(allErrStrs, "empty k8s token and empty cert or key")
		}
	} else if !strings.HasPrefix(f.K8sApiServer, "http") {
		allErrStrs = append(allErrStrs, fmt.Sprintf("k8s api server should start with https or http ,got %s", f.K8sApiServer))
	}
	if len(allErrStrs) > 0 {
		return fmt.Errorf("%s", strings.Join(allErrStrs, "\n"))
	}
	return nil
}
