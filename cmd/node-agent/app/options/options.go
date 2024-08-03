package options

import (
	"github.com/cni/pkg/util/etcd"
	"github.com/cni/pkg/util/k8s"
	"github.com/cni/pkg/util/server"
	"github.com/spf13/pflag"
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
	HostName     string `json:"host_name"`
	HostIP       string `json:"host_ip"`
}

type K8sFlags struct {
	*k8s.Flags
}

type EtcdFlags struct {
	*etcd.Flags
}

type NodeAgentFlags struct {
	AgentHost string `json:"agent_host"`
	AgentPort string `json:"agent_port"`
	K8sFlags
	EtcdFlags
}

func NewNodeAgentFlags() *NodeAgentFlags {
	return &NodeAgentFlags{
		AgentHost: "0.0.0.0",
		AgentPort: "9102",
		K8sFlags:  K8sFlags{k8s.NewK8sFlags()},
		EtcdFlags: EtcdFlags{etcd.NewEtcdFlags()},
	}
}

func (s *NodeAgentFlags) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.AgentHost, "agent-host", s.AgentHost, "the bind host of node agent")
	fs.StringVar(&s.AgentPort, "agent-port", s.AgentPort, "the bind port of node agent")
	s.K8sFlags.AddFlags(fs)
	s.EtcdFlags.AddFlags(fs)
}
