package ipam

import (
	"errors"
	"fmt"
	"github.com/cni/cmd/node-agent/app/options"
	"github.com/cni/pkg/util/etcd"
	"github.com/cni/pkg/util/k8s"
	"github.com/containernetworking/plugins/pkg/ip"
	clientv3 "go.etcd.io/etcd/client/v3"
	"k8s.io/klog/v2"
	"net"
	"time"
)

const prefix = "cni/ipam"

//	type Get struct {
//		etcdClient  *etcd.EtcdClient
//		k8sClient   *client.LightK8sClient
//		nodeIpCache map[string]string
//		cidrCache   map[string]string
//	}
//
//	type Release struct {
//		etcdClient *etcd.EtcdClient
//		k8sClient  *client.LightK8sClient
//	}
//
//	type Set struct {
//		etcdClient *etcd.EtcdClient
//		k8sClient  *client.LightK8sClient
//	}
//
//	type operators struct {
//		Get     *Get
//		Set     *Set
//		Release *Release
//	}
//
//	type operator struct {
//		*operators
//	}
//
//	type Network struct {
//		Name          string
//		IP            string
//		Hostname      string
//		CIDR          string
//		IsCurrentHost bool
//	}
//
//	type IpamService struct {
//		Subnet             string
//		MaskSegment        string
//		MaskIP             string
//		PodMaskSegment     string
//		PodMaskIP          string
//		CurrentHostNetwork string
//		EtcdClient         *etcd.EtcdClient
//		K8sClient          *client.LightK8sClient
//		*operator
//	}
//
//	type IPAMOptions struct {
//		MaskSegment      string
//		PodIpMaskSegment string
//		RangeStart       string
//		RangeEnd         string
//	}
//
// var _lock sync.Mutex
// var _isLocking bool
//
//	func unlock() {
//		if _isLocking {
//			_lock.Unlock()
//			_isLocking = false
//		}
//	}
//
//	func lock() {
//		if !_isLocking {
//			_lock.Lock()
//			_isLocking = true
//		}
//	}
//func GetLightK8sClient() *client.LightK8sClient {
//	paths, err := helper.GetHostAuthenticationInfoPath()
//	if err != nil {
//		klog.Errorf("failed to GetHostAuthenticationInfoPath,err is %v", err)
//	}
//	client.Init(paths.CaPath, paths.CertPath, paths.KeyPath)
//	k8sClient, err := client.GetLightK8sClient()
//	if err != nil {
//		return nil
//	}
//	return k8sClient
//}

type IpamDriver struct {
	K8sClient   *k8s.Client
	EtcdClient  *etcd.Client
	NetWorkName string
	Mu          *etcd.EtcdMutex
	//nodeIpCache map[string]string
	//cidrCache   map[string]string
}

func NewIpamDriver(na *options.NodeAgent, networkName string) (*IpamDriver, error) {
	ipam := &IpamDriver{
		K8sClient:   na.K8sAgent,
		EtcdClient:  na.EtcdAgent,
		NetWorkName: networkName,
	}

	key := etcd.NetWorkCrdLocksKey(networkName)
	mu := etcd.NewMutex(key, ipam.EtcdClient.Client)
	ipam.Mu = mu
	return ipam, nil
}

func AllocateIP(subnet *net.IPNet, AllocateIPMap map[string]string) (net.IP, error) {
	// Get the network address and mask length from the subnet.
	netAddr := subnet.IP.Mask(subnet.Mask)

	// Iterate over the IP addresses within the subnet.
	for ipAddr := netAddr.Mask(subnet.Mask); subnet.Contains(ipAddr); Inc(ipAddr) {
		// Skip the network and broadcast addresses.
		_, ok := AllocateIPMap[ipAddr.String()]
		if ipAddr.Equal(subnet.IP) || ipAddr.Equal(ones(subnet.IP)) || ok {
			continue
		}
		AllocateIPMap[ipAddr.String()] = "1"
		// Return the currently allocated IP address.
		return ipAddr, nil
	}

	// If no valid IP address found, return an error.
	return nil, fmt.Errorf("no available IP address in the subnet")
}

// Inc Increment IP address
func Inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ones Get the broadcast address
func ones(ip net.IP) net.IP {
	ipLen := len(ip)
	result := make(net.IP, ipLen)
	for i := 0; i < ipLen; i++ {
		result[i] = 255
	}
	return result
}

func (ipam *IpamDriver) AllocationIpFromNetwork(network string) (ipaddr, gw *ip.IP, opts []clientv3.Op, err error) {
	for i := 0; i < 10; i++ {
		if err = ipam.Mu.Lock(); err == nil {
			break
		} else {
			time.Sleep(time.Millisecond)
		}
	}
	defer ipam.Mu.Unlock()
	networkKey := etcd.NetworkKey(network)
	networkCrd, err := ipam.EtcdClient.GetNetwork(networkKey)
	if err != nil {
		klog.Errorf("failed to get network %v from etcd ", network)
		errMsg := fmt.Sprintf("failed to get network %v from etcd ", network)
		return nil, nil, opts, errors.New(errMsg)
	}
	if len(networkCrd.Subnets) == 0 {
		klog.Errorf("network %v don't have subnet ", network)
		errMsg := fmt.Sprintf("network %v don't have subnet ", network)
		return nil, nil, opts, errors.New(errMsg)
	}
	for _, subnet := range networkCrd.Subnets {
		_, ipNet, err := net.ParseCIDR(subnet.CIDR)
		if err != nil {
			klog.Errorf("failed to parse subnet %v cidr of network %v")
			continue
		}
		newIP, err := AllocateIP(ipNet, subnet.AllocatedIps)
		if err != nil {
			klog.Errorf("failed to AllocateIP ,err is %v", err)
			continue
		}
		ipaddr.IPNet = *ipNet
		ipaddr.IP = newIP
		subnet.AllocatedIps[newIP.String()] = "1"
		gw.IPNet = *ipNet
		gw.IP = net.ParseIP(subnet.Gateway)
		break
	}
	if ipaddr == nil || gw == nil {
		klog.Errorf("failed AllocateIP for pod from network %v", network)
		errMsg := fmt.Sprintf("failed AllocateIP for pod from network %v", network)
		return ipaddr, gw, opts, errors.New(errMsg)
	}
	op, err := etcd.OpPutObject(network, networkCrd)
	if err != nil {
		return nil, nil, nil, err
	} else {
		opts = append(opts, op)
	}
	return ipaddr, gw, opts, nil
}

func (ipam *IpamDriver) ReleaseIpFromNetwork(network string, ip string) (opts []clientv3.Op, err error) {
	for i := 0; i < 10; i++ {
		if err = ipam.Mu.Lock(); err == nil {
			break
		} else {
			time.Sleep(time.Millisecond)
		}
	}
	defer ipam.Mu.Unlock()
	networkCrd, err := ipam.EtcdClient.GetNetwork(network)
	if err != nil {
		klog.Errorf("failed to get network %v from etcd ", network)
		errMsg := fmt.Sprintf("failed to get network %v from etcd ", network)
		return opts, errors.New(errMsg)
	}
	if len(networkCrd.Subnets) == 0 {
		klog.Errorf("network %v don't have subnet ", network)
		errMsg := fmt.Sprintf("network %v don't have subnet ", network)
		return opts, errors.New(errMsg)
	}
	for _, subnet := range networkCrd.Subnets {
		_, ipNet, err := net.ParseCIDR(subnet.CIDR)
		if err != nil {
			klog.Errorf("failed to parse subnet %v cidr of network %v")
			continue
		}
		ipaddr := net.ParseIP(ip)
		if ipNet.Contains(ipaddr) {
			delete(subnet.AllocatedIps, ip)
			break
		}
	}
	op, err := etcd.OpPutObject(network, networkCrd)
	if err != nil {
		opts = append(opts, op)
	}
	return opts, nil
}
