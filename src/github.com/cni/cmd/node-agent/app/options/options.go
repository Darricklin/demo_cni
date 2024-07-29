package options

import (
	"github.com/cni/pkg/util/etcd"
	"github.com/cni/pkg/util/ipam"
	"github.com/cni/pkg/util/k8s"
	"github.com/cni/pkg/util/server"
	"k8s.io/client-go/kubernetes"
	"sync"
)

type NodeAgent struct {
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
	K8sFlags
	EtcdFlags
}
