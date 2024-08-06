package main

import (
	"fmt"
	"github.com/vishvananda/netlink"
)

func main() {
	ens192, err := netlink.LinkByName("ens192")
	if err != nil {
		fmt.Printf("failed get netlinkens192,err is %s", err)
	}
	calif8beb26591f, err := netlink.LinkByName("calif8beb26591f")
	if err != nil {
		fmt.Printf("failed get calif8beb26591f,err is %s", err)
	}
	fmt.Printf("calif8beb26591f is %+v\n", calif8beb26591f)
	fmt.Printf("ens192 is %+v\n", ens192)
	ensIPs, err := netlink.AddrList(ens192, netlink.FAMILY_ALL)
	if err != nil {
		fmt.Printf("failed to get ens192 ip,err %v\n", err)
	}
	fmt.Printf("ens192IPs is %+v\n", ensIPs)
	calIPs, err := netlink.AddrList(calif8beb26591f, netlink.FAMILY_ALL)
	if err != nil {
		fmt.Printf("failed to get calif8beb26591f ip,err %v\n", err)
	}
	fmt.Printf("calif8beb26591f is %+v\n", calIPs)

}
