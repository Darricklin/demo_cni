package ipam

import (
	"fmt"
	"github.com/cni/pkg/util/etcd"
	"github.com/containernetworking/plugins/pkg/ip"
	"net"
	"testing"
)

func TestAllocateIP(t *testing.T) {
	subnet := etcd.Subnet{
		Name:      "",
		CIDR:      "10.0.0.0/24",
		Allocated: map[string]string{},
		Reserved:  map[string]string{"10.0.0.1": "1", "10.0.0.2": "1"},
		IpVersion: 0,
		Gateway:   "",
	}
	_, ipNet, _ := net.ParseCIDR(subnet.CIDR)
	var podIp ip.IP
	for ipaddr := range subnet.Reserved {
		podIp.IP = net.ParseIP(ipaddr)
		break
	}
	podIp.Mask = ipNet.Mask
	fmt.Printf("podip %+v", podIp)
}
