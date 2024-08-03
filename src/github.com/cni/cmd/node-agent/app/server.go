package app

import (
	"context"
	"crypto/rand"
	"fmt"
	"github.com/cni/cmd/node-agent/app/constants"
	"github.com/cni/cmd/node-agent/app/options"
	"github.com/cni/pkg/util/etcd"
	"github.com/cni/pkg/util/ipam"
	"github.com/cni/pkg/util/k8s"
	"github.com/cni/pkg/util/rest"
	"github.com/containernetworking/cni/pkg/types"
	types020 "github.com/containernetworking/cni/pkg/types/020"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/emicklei/go-restful/v3"
	"github.com/vishvananda/netlink"
	clientv3 "go.etcd.io/etcd/client/v3"
	"io"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"net"
	"net/http"
	"os"
	"time"
)

func RUN(na *options.NodeAgent) error {
	err := run(na)
	if err != nil {
		na.Cancel()
	}
	select {
	case <-na.Done():
		na.StopWg.Wait()
		break
	}
	return err
}

func run(na *options.NodeAgent) error {
	if err := initEtcd(na); err != nil {
		klog.Errorf("failed to init etcd ,err is %s", err)
		return err
	}
	if err := initK8s(na); err != nil {
		klog.Errorf("failed to init k8s ,err is %s", err)
		return err
	}
	if err := initServer(na); err != nil {
		klog.Errorf("failed to init node agent server ,err is %s", err)
		return err
	}
	if err := initHttpServer(na); err != nil {
		klog.Errorf("failed to init node agent health server ,err is %s", err)
	}
	return nil
}
func initEtcd(na *options.NodeAgent) error {
	klog.Infof("init etcd agent")
	cli, err := etcd.NewClient(na.EtcdFlags.Flags)
	if err != nil {
		return fmt.Errorf("failed to create etcd client: %s", err)
	}
	na.EtcdAgent = cli
	klog.Infof("init etcd agent succeed")
	return nil
}
func initK8s(na *options.NodeAgent) error {
	klog.Infof("init k8s agent")
	k8sAgent, err := k8s.NewClient(na.K8sFlags.Flags)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %s", err)
	}
	na.K8sAgent = k8sAgent
	klog.Infof("init k8s agent succeed")
	klog.Infof("init k8s clientSet")
	k8sConfig, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		return fmt.Errorf("failed to build k8s clientSet config: %s", err)
	}
	k8sClientSet, err := clientset.NewForConfig(k8sConfig)
	if err != nil {
		return fmt.Errorf("failed to build k8s clientSet : %s", err)
	}
	na.K8sClientSet = k8sClientSet
	klog.Infof("init k8sClientSet succeed")
	return nil
}

func initServer(na *options.NodeAgent) error {
	klog.Info("init node agent server ")
	wsContainer := restful.NewContainer()
	wsContainer.Router(restful.CurlyRouter{})
	ws := new(restful.WebService)
	ws.Path(constants.Base).Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)
	ws.Route(ws.POST(constants.Ports).
		To(CreatePod(na)).
		Doc("create a pod").
		Reads(Pod{}).
		Writes(PodResponse{}).
		Returns(http.StatusOK, http.StatusText(http.StatusOK), PodResponse{}).
		Returns(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), PodResponse{}))
	ws.Route(ws.DELETE(fmt.Sprintf("%s/{%s}/{%s}/{%s}", constants.Ports, constants.PodNameSpace, constants.PodName, constants.IFName)).
		To(DeletePod(na)).
		Doc("delete a Pod").
		Param(ws.PathParameter(constants.PodNameSpace, "identifier of the pod namespace").DataType("string")).
		Param(ws.PathParameter(constants.PodName, "identifier of the pod name").DataType("string")).
		Param(ws.PathParameter(constants.IFName, "identifier of the ifname").DataType("string")).
		Returns(http.StatusNoContent, http.StatusText(http.StatusNoContent), nil))
	ws.Route(ws.GET(constants.Health).To(GetHealth(na)).
		Doc("get server health").
		Writes(HealthResp{}).
		Returns(http.StatusOK, http.StatusText(http.StatusOK), HealthResp{}))
	ws.Route(ws.GET(constants.Version).To(GetVersion(na)).
		Doc("get server health").
		Writes(VersionResp{}).
		Returns(http.StatusOK, http.StatusText(http.StatusOK), VersionResp{}))
	wsContainer.Add(ws)
	unixListener, err := rest.NewUnixListener(constants.NodeAgentSock)
	if err != nil {
		return fmt.Errorf("failed to create sock %s : %v", constants.NodeAgentSock, err)
	}
	na.StopWg.Add(1)
	go startServer(na, &http.Server{Handler: wsContainer}, unixListener)
	return nil
}

func initHttpServer(na *options.NodeAgent) error {
	klog.Info("init node agent health server ")
	wsContainer := restful.NewContainer()
	wsContainer.Router(restful.CurlyRouter{})
	ws := new(restful.WebService)
	ws.Path(constants.Base).Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)
	ws.Route(ws.GET(constants.Health).To(GetHealth(na)).
		Doc("get server health").
		Writes(HealthResp{}).
		Returns(http.StatusOK, http.StatusText(http.StatusOK), HealthResp{}))
	ws.Route(ws.GET(constants.Version).To(GetVersion(na)).
		Doc("get server health").
		Writes(VersionResp{}).
		Returns(http.StatusOK, http.StatusText(http.StatusOK), VersionResp{}))
	wsContainer.Add(ws)
	addr := fmt.Sprintf("%s:%s", na.AgentHost, na.AgentPort)
	listenAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return err
	}
	na.StopWg.Add(1)
	go startServer(na, &http.Server{Handler: wsContainer}, listener)
	return nil
}

type Pod struct {
	Name        string          `json:"name"`
	Namespace   string          `json:"namespace"`
	ContainerId string          `json:"container_id"`
	NetNs       string          `json:"net_ns"`
	IfName      string          `json:"if_name"`
	MTU         int             `json:"mtu"`
	Result      types020.Result `json:"result"`
	HostId      string          `json:"binding:host-id"`
}

type PodResponse struct {
	Port   Port            `json:"port"`
	Result types020.Result `json:"result"`
}
type Port struct {
}

type HealthResp struct {
	Health string `json:"health"`
}
type VersionResp struct {
	Version string `json:"version"`
}

func startServer(na *options.NodeAgent, server *http.Server, listener net.Listener) {
	defer na.StopWg.Done()
	stopCh := make(chan struct{})
	go func() {
		if err := server.Serve(listener); err != nil {
			klog.Error("failed to start server,err is %s", err)
			close(stopCh)
		}
	}()
	select {
	case <-na.Done():
		klog.Errorf("receive na done, shutdown node agent")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := server.Shutdown(ctx); err != nil {
			klog.Error(err)
		}
		cancel()
		<-stopCh
		break
	case <-stopCh:
		na.Cancel()
		break
	}
}
func GetHealth(_ *options.NodeAgent) func(request *restful.Request, response *restful.Response) {
	return func(request *restful.Request, response *restful.Response) {
		health := HealthResp{Health: "ok"}
		if err := response.WriteEntity(health); err != nil {
			klog.Error(err)
		}
	}
}
func GetVersion(_ *options.NodeAgent) func(request *restful.Request, response *restful.Response) {
	return func(request *restful.Request, response *restful.Response) {
		version := VersionResp{
			Version: "v1.0",
		}
		if err := response.WriteEntity(version); err != nil {
			klog.Error(err)
		}
	}
}

func CreatePod(na *options.NodeAgent) func(request *restful.Request, response *restful.Response) {
	return func(request *restful.Request, response *restful.Response) {
		ProcessCreatePod(na, request, response, createPodWithLock)
	}
}

func ProcessCreatePod(na *options.NodeAgent, request *restful.Request, response *restful.Response,
	createPodFunc func(*options.NodeAgent, Pod) (int, PodResponse, error)) {
	var pod Pod
	if err := request.ReadEntity(&pod); err != nil {
		klog.Error(err)
		return
	}
	klog.Infof("create pod request received: body is %+v", pod)
	code, resp, err := createPodFunc(na, pod)
	if err != nil {
		klog.Error(err, code)
		return
	}
	if err = response.WriteEntity(resp); err != nil {
		klog.Error(err)
	}
}

func GetNetconf(na *options.NodeAgent, ns, name string) (string, string, error) {
	labels, annos, podIP, err := na.K8sAgent.GetPodAnnoAndLabels(ns, name)
	if err != nil {
		return "", "", err
	}
	if networkName, ok := annos[constants.NETWORK]; ok {
		if networkName != "" {
			return networkName, podIP, nil
		} else {
			return "", "", fmt.Errorf("wrong network")
		}
	} else if networkName, ok := labels[constants.NETWORK]; ok {
		if networkName != "" {
			return networkName, podIP, nil
		} else {
			return "", "", fmt.Errorf("wrong network")
		}
	}
	return "", "", fmt.Errorf("no network find")
}

func GeneratePortRandomMacAddress() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	macAddr := fmt.Sprintf("de:%02x:%02x:%02x:%02x:%02x", buf[1], buf[2], buf[3], buf[4], buf[5])
	return macAddr
}

func createPodWithLock(na *options.NodeAgent, pod Pod) (int, PodResponse, error) {
	na.Locker.Lock()
	defer na.Locker.Unlock()
	var podResp PodResponse
	var opts []clientv3.Op
	network, _, err := GetNetconf(na, pod.Namespace, pod.Name)
	if err != nil {
		return 400, podResp, err
	}
	result := &types100.Result{
		CNIVersion: pod.Result.CNIVersion,
	}
	ipamDriver, err := ipam.NewIpamDriver(na, network)
	if err != nil {
		return 0, podResp, fmt.Errorf("failed to get ipamDriver of network %s", network)
	}
	podIp, gwIp, ipOps, err := ipamDriver.AllocationIpFromNetwork(network)
	if err != nil {
		klog.Error(err)
	}
	opts = append(opts, ipOps...)
	ifmac := GeneratePortRandomMacAddress()
	podNs, err := ns.GetNS(pod.NetNs)
	if err != nil {
		klog.Error(err)
	}
	hostVethName := constants.HostVethPre + pod.ContainerId[:Min(11, len(pod.ContainerId))]
	hostInterface, contInterface, err := SetupVethPair(pod.IfName, ifmac, hostVethName, podIp, gwIp, 1500, podNs)
	if err != nil {
		klog.Error(err)
	}
	result.Interfaces = []*types100.Interface{hostInterface, contInterface}
	podIpconfig := &types100.IPConfig{
		Interface: types100.Int(1),
		Address:   podIp.IPNet,
		Gateway:   gwIp.IP,
	}
	result.IPs = []*types100.IPConfig{podIpconfig}
	etcdCli, err := etcd.NewClient(etcd.NewEtcdFlags())
	if err != nil {
		return 400, podResp, err
	}
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	if _, err := etcdCli.Txn(ctx).Then(opts...).Commit(); err != nil {
		// rollback
		return 400, podResp, err
	}
	return 400, podResp, nil
}

func DeletePod(na *options.NodeAgent) func(request *restful.Request, response *restful.Response) {
	return func(request *restful.Request, response *restful.Response) {
		ProcessDeletePod(na, request, response, deletePodWithLock)
	}
}

func ProcessDeletePod(na *options.NodeAgent, request *restful.Request, response *restful.Response,
	deletePodFunc func(*options.NodeAgent, string, string, string) (int, error)) {
	namespace := request.PathParameter(constants.PodNameSpace)
	name := request.PathParameter(constants.PodName)
	containerId := request.PathParameter(constants.ContainerId)
	code, err := deletePodFunc(na, namespace, name, containerId)
	if err != nil {
		klog.Error(err)
	}
	response.WriteHeader(code)
}

func deletePodWithLock(na *options.NodeAgent, namespace, name, ifname string) (int, error) {
	na.Locker.Lock()
	defer na.Locker.Unlock()
	var opts []clientv3.Op
	network, podIp, err := GetNetconf(na, namespace, name)
	if err != nil {
		return 0, err
	}
	ipamDriver, err := ipam.NewIpamDriver(na, network)
	if err != nil {
		return 0, fmt.Errorf("failed to get ipamDriver of network %s", network)
	}
	networkOps, err := ipamDriver.ReleaseIpFromNetwork(network, podIp)
	if err != nil {
		return 0, err
	}
	podNs, err := ns.GetNS(namespace)
	if err != nil {
		klog.Errorf("failed to get ns of pod %s %s", namespace, name)
		return 0, err
	}
	opts = append(opts, networkOps...)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	if _, err = na.EtcdAgent.Client.Txn(ctx).Then(opts...).Commit(); err != nil {
		return 0, err
	}
	startTime := time.Now()
	done := make(chan struct{})
	var nsErr, linkErr error
	go func() {
		defer close(done)
		nsErr = podNs.Do(func(netNS ns.NetNS) error {
			var iface netlink.Link
			iface, linkErr = netlink.LinkByName(ifname)
			if linkErr != nil {
				linkErr = netlink.LinkDel(iface)
			}
			return nil
		})
	}()
	select {
	case <-done:
		if nsErr != nil {
			if _, ok := nsErr.(ns.NSPathNotExistErr); ok {
				klog.Infof("netns already gone ,nothing to do")
				return 204, nil
			}
			return 0, fmt.Errorf("failed to enter netns %v", nsErr)
		}
		if linkErr != nil {
			if _, ok := linkErr.(netlink.LinkNotFoundError); ok {
				klog.Infof("veth already gone,nothing to do ")
				return 204, nil
			}
			return 0, fmt.Errorf("failed to clean up veth inside netns : %v", linkErr)
		}
		klog.Infof("after %v,delete device in netns ", time.Since(startTime))
	case <-time.After(20 * time.Second):
		return 0, fmt.Errorf("timeout deleting device in netns %s", namespace)
	}
	return 204, nil
}

func writeProcSys(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, err := f.Write([]byte(value))
	if err == nil && n < len(value) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

func configureSysctls(hostVethName string, hasIPv4, hasIPv6 bool) error {
	var err error

	if hasIPv4 {
		// Enable routing to localhost.  This is required to allow for NAT to the local
		// host.
		err := writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/route_localnet", hostVethName), "1")
		if err != nil {
			return fmt.Errorf("failed to set net.ipv4.conf.%s.route_localnet=1: %s", hostVethName, err)
		}

		// Normally, the kernel has a delay before responding to proxy ARP but we know
		// that's not needed in a Calico network so we disable it.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", hostVethName), "0"); err != nil {
			klog.Warningf("failed to set net.ipv4.neigh.%s.proxy_delay=0: %s", hostVethName, err)
		}

		// Enable proxy ARP, this makes the host respond to all ARP requests with its own
		// MAC. We install explicit routes into the containers network
		// namespace and we use a link-local address for the gateway.  Turing on proxy ARP
		// means that we don't need to assign the link local address explicitly to each
		// host side of the veth, which is one fewer thing to maintain and one fewer
		// thing we may clash over.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", hostVethName), "1"); err != nil {
			return fmt.Errorf("failed to set net.ipv4.conf.%s.proxy_arp=1: %s", hostVethName, err)
		}

		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", hostVethName), "1"); err != nil {
			return fmt.Errorf("failed to set net.ipv4.conf.%s.forwarding=1: %s", hostVethName, err)
		}
	}

	if hasIPv6 {
		// Make sure ipv6 is enabled on the hostVeth interface in the host network namespace.
		// Interfaces won't get a link local address without this sysctl set to 0.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", hostVethName), "0"); err != nil {
			return fmt.Errorf("failed to set net.ipv6.conf.%s.disable_ipv6=0: %s", hostVethName, err)
		}

		// Enable proxy NDP, similarly to proxy ARP, described above in IPv4 section.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/proxy_ndp", hostVethName), "1"); err != nil {
			return fmt.Errorf("failed to set net.ipv6.conf.%s.proxy_ndp=1: %s", hostVethName, err)
		}

		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/forwarding", hostVethName), "1"); err != nil {
			return fmt.Errorf("failed to set net.ipv6.conf.%s.forwarding=1: %s", hostVethName, err)
		}
	}

	if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_ra", hostVethName), "0"); err != nil {
		klog.Warningf("failed to set net.ipv6.conf.%s.accept_ra=0: %s", hostVethName, err)
	}

	return nil
}

func SetupVethPair(ifName, podMac, hostVethName string, podIp, podGw *ip.IP, mtu int, netNs ns.NetNS) (*types100.Interface, *types100.Interface, error) {
	hostinterface := &types100.Interface{}
	continterface := &types100.Interface{}
	// 创建vethpair，配置容器ip，默认路由，mtu
	err := netNs.Do(func(hostNs ns.NetNS) error {
		_, containerVeth, err := ip.SetupVethWithName(ifName, hostVethName, mtu, podMac, hostNs)
		if err != nil {
			return err
		}
		continterface.Name = containerVeth.Name
		continterface.Mac = containerVeth.HardwareAddr.String()
		continterface.Sandbox = netNs.Path()
		contlink, err := netlink.LinkByName(containerVeth.Name)
		if err != nil {
			return err
		}

		err = netlink.AddrAdd(contlink, &netlink.Addr{IPNet: &podIp.IPNet})
		if err != nil {
			return err
		}
		defaultNet := net.IPNet{}
		if podIp.IP.To4() != nil {
			defaultNet.IP = net.IPv4zero
		} else {
			defaultNet.IP = net.IPv6zero
		}
		if podGw.IP == nil {
			podGw.IP = net.IPv4(169, 254, 1, 1)
		}
		defaultRoute := &types.Route{Dst: defaultNet, GW: podGw.IP}
		err = ip.AddRoute(&defaultRoute.Dst, defaultRoute.GW, contlink)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetMTU(contlink, mtu); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return hostinterface, continterface, err
	}

	// 配置默认的mac，mtu，路由
	hostlink, err := netlink.LinkByName(hostVethName)
	if err != nil {
		return hostinterface, continterface, err
	}
	hardwareaddr, err := net.ParseMAC(constants.HostVethMac)
	if err != nil {
		return hostinterface, continterface, err
	}
	if err := netlink.LinkSetHardwareAddr(hostlink, hardwareaddr); err != nil {
		return hostinterface, continterface, err
	}
	if err := netlink.LinkSetMTU(hostlink, mtu); err != nil {
		return hostinterface, continterface, err
	}
	hostinterface.Name = hostVethName
	hostinterface.Mac = constants.HostVethMac
	podIPNet := net.IPNet{}
	hasIpv4 := false
	hasIpv6 := false
	if podIp.IP.To4() != nil {
		podIPNet.IP = podIp.IP.To4()
		podIPNet.Mask = net.CIDRMask(32, 32)
		hasIpv4 = true
	} else {
		podIPNet.IP = podIp.IP.To16()
		podIPNet.Mask = net.CIDRMask(128, 128)
		hasIpv6 = true
	}
	defaultRoute := &types.Route{Dst: podIPNet, GW: podGw.IP}
	err = ip.AddRoute(&defaultRoute.Dst, defaultRoute.GW, hostlink)
	if err != nil {
		return hostinterface, continterface, err
	}
	err = configureSysctls(hostVethName, hasIpv4, hasIpv6)
	if err != nil {
		return hostinterface, continterface, err
	}
	return hostinterface, continterface, err
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
