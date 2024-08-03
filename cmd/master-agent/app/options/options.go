package options

import (
	"github.com/cni/pkg/util/etcd"
	"github.com/cni/pkg/util/ipam"
	"github.com/cni/pkg/util/k8s"
	"github.com/cni/pkg/util/server"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"sync"
)

type MasterAgent struct {
	*server.Server
	MasterAgentFlags
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

type MasterAgentFlags struct {
	BindHost        string `json:"bind-host"`
	BindPort        string `json:"bind-port"`
	WebHookBindPort string `json:"webhook-bind-port"`
	TlsCertPath     string `json:"tlsCertPath"`
	TlsKeyPath      string `json:"tlsKeyPath"`
	K8sFlags
	EtcdFlags
}

func NewMasterFlags() *MasterAgentFlags {
	return &MasterAgentFlags{
		BindHost:        "0.0.0.0",
		BindPort:        "9100",
		WebHookBindPort: "9101",
		TlsCertPath:     "",
		TlsKeyPath:      "",
		K8sFlags:        K8sFlags{k8s.NewK8sFlags()},
		EtcdFlags:       EtcdFlags{etcd.NewEtcdFlags()},
	}
}

func (s *MasterAgentFlags) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.BindHost, "bind-host", s.BindHost, "the bind host of master agent")
	fs.StringVar(&s.BindPort, "bind-port", s.BindPort, "the bind port of master agent")
	fs.StringVar(&s.WebHookBindPort, "webhook-bind-port", s.WebHookBindPort, "the webhook bind port of master agent")
	fs.StringVar(&s.TlsCertPath, "tlsCertPath", s.TlsCertPath, "the tlsCertPath of webhook")
	fs.StringVar(&s.TlsKeyPath, "tlsKeyPath", s.TlsKeyPath, "the tlsKeyPath of webhook")
	s.K8sFlags.AddFlags(fs)
	s.EtcdFlags.AddFlags(fs)
}
