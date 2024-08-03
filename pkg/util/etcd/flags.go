package etcd

import (
	"fmt"
	"github.com/spf13/pflag"
)

type Flags struct {
	EtcdServers  []string `json:"etcd-servers"`
	EtcdCertFile string   `json:"etcd-certfile"`
	EtcdKeyFile  string   `json:"etcd-keyfile"`
	EtcdCAFile   string   `json:"etcd-cafile"`
}

func NewEtcdFlags() *Flags {
	return &Flags{
		EtcdServers: []string{"127.0.0.1:2379"},
	}
}

func (s *Flags) AddFlags(fs *pflag.FlagSet) {
	fs.StringSliceVar(&s.EtcdServers, "etcd-servers", s.EtcdServers, "the etcd server endpoints")
	fs.StringVar(&s.EtcdCertFile, "etcd-certfile", s.EtcdCertFile, "the etcd server Cert file")
	fs.StringVar(&s.EtcdKeyFile, "etcd-keyfile", s.EtcdKeyFile, "the etcd server key file")
	fs.StringVar(&s.EtcdCAFile, "etcd-cafile", s.EtcdCAFile, "the etcd server CA file")
}
func (s *Flags) ValidateFlags() error {
	if len(s.EtcdServers) == 0 {
		return fmt.Errorf("empty etcd servers")
	}
	return nil
}
