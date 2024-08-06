package app

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"testing"
)

func TestSetupVethPair(t *testing.T) {
	ens192, err := netlink.LinkByName("ens192")
	if err != nil {
		fmt.Printf("failed get netlinkens192,err is %s", err)
	}
	calif8beb26591f, err := netlink.LinkByName("calif8beb26591f")
	if err != nil {
		fmt.Printf("failed get calif8beb26591f,err is %s", err)
	}
	fmt.Printf("calif8beb26591f is %+v", calif8beb26591f)
	fmt.Printf("ens192 is %+v", ens192)
}
