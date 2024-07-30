package options

import (
	"github.com/cni/pkg/util/etcd"
	"github.com/cni/pkg/util/ipam"
	"github.com/cni/pkg/util/k8s"
	"github.com/cni/pkg/util/server"
	"k8s.io/client-go/kubernetes"
	"sync"
)

type MasterAgent struct {
	*server.Server
	NodeAgentFlags
	EtcdAgent    *etcd.Client
	K8sAgent     *k8s.Client
	K8sClientSet *kubernetes.Clientset
	Locker       sync.Mutex
	Ipam         ipam.IpamDriver
}

type K8sFlags struct {
	*k8s.Flags
}

type EtcdFlags struct {
	*etcd.Flags
}

type NodeAgentFlags struct {
	BindHost        string `json:"bind_host"`
	BindPort        string `json:"bind_port"`
	WebHookBindPort string `json:"web_hook_bind_port"`
	CertPath        string `json:"cert_path"`
	KeyPath         string `json:"key_path"`
	K8sFlags
	EtcdFlags
}
