package main

import (
	"fmt"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"log"
	"net"
)

func main() {
	netNs, err := ns.GetNS("/var/run/netns/default")
	if err != nil {
		log.Fatalf("Error getting network namespace: %v\n", err)
	}
	podIp := net.IPNet{
		IP:   net.ParseIP("10.0.0.10"),
		Mask: net.CIDRMask(32, 32),
	}
	//podGw := net.IPNet{
	//	IP:   net.ParseIP("169.254.1.1"),
	//	Mask: net.CIDRMask(24, 32),
	//}
	err = netNs.Do(func(hostNS ns.NetNS) error {
		_, contVeth, err := ip.SetupVethWithName("eth0", "eth10", 1500, "de:cd:d6:76:07:84", hostNS)
		if err != nil {
			fmt.Printf("failed to setup contVeth,err is %s", err)
			return err
		}
		fmt.Printf("contVeth is %+v\n", contVeth)
		contLink, err := netlink.LinkByName(contVeth.Name)
		if err != nil {
			fmt.Printf("failed to find link: %v", err)
			return fmt.Errorf("failed to find link: %v", err)
		}
		fmt.Printf("contLink is %+v\n", contLink)
		if err = netlink.LinkSetUp(contLink); err != nil {
			fmt.Printf("failed to setUp contlink, err is %v\n", err)
			return fmt.Errorf("failed to setUp contlink, err is %v\n", err)
		}
		err = netlink.AddrAdd(contLink, &netlink.Addr{IPNet: &podIp})
		if err != nil {
			fmt.Printf("failed to add IP address: %v", err)
			return fmt.Errorf("failed to add IP address: %v", err)
		}
		ipaddrs, err := netlink.AddrList(contLink, netlink.FAMILY_ALL)
		if err != nil {
			fmt.Printf("failed to get ipaddr ,err is %v\n", err)
			return fmt.Errorf("failed to get ipaddr ,err is %v\n", err)
		}
		fmt.Printf("ipaddr is %+v\n", ipaddrs)
		gw := net.IPv4(169, 254, 1, 1)
		gwNet := &net.IPNet{IP: gw, Mask: net.CIDRMask(32, 32)}
		err = netlink.RouteAdd(
			&netlink.Route{
				LinkIndex: contLink.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       gwNet,
			})
		if err != nil {
			fmt.Printf("failed to add gw route: %v", err)
			return fmt.Errorf("failed to add gw route: %v", err)
		}
		if err := ip.AddDefaultRoute(gw, contLink); err != nil {
			fmt.Printf("failed to add default route: %v", err)
			return fmt.Errorf("failed to add default route: %v", err)
		}

		return nil
	})

	//err = netNs.Do(func(hostNs ns.NetNS) error {
	//	// 查找 Pod 的网络接口
	//
	//	link, err := netlink.LinkByName("eth0")
	//	if err != nil {
	//		return fmt.Errorf("failed to find link: %v", err)
	//	}
	//
	//	// 配置 Pod 的 IP 地址
	//	err = netlink.AddrAdd(link, &netlink.Addr{IPNet: &podIp})
	//	if err != nil {
	//		return fmt.Errorf("failed to add IP address: %v", err)
	//	}
	//
	//	// 添加默认路由
	//	defaultRoute := netlink.Route{
	//		Dst: &net.IPNet{
	//			IP:   net.IPv4zero,
	//			Mask: net.CIDRMask(0, 32),
	//		},
	//		Gw: podGw.IP,
	//	}
	//
	//	err = netlink.RouteAdd(&defaultRoute)
	//	if err != nil {
	//		return fmt.Errorf("failed to add route: %v", err)
	//	}
	//
	//	return nil
	//})

	if err != nil {
		log.Fatalf("Error in network namespace: %v\n", err)
	} else {
		fmt.Println("Network namespace setup completed successfully")
	}

}
