package constants

const (
	NodeAgentSock = "/run/node-agent-cni/node-agent-cni.sock"
	Base          = "/v1.0"
	Ports         = "/ports"
	Health        = "/health"
	PodName       = "pod-name"
	PodNameSpace  = "pod-namespace"
	ContainerId   = "container-id"
	IFName        = "ifname"
	Netns         = "netns"
	Version       = "/version"
)

const (
	NETWORK     = "k8s.cni.cncf.io/network"
	HostVethMac = "ee:ee:ee:ee:ee:ee"
	HostVethPre = "tap"
)

const AgentNodeIP = "HOST_IP"
