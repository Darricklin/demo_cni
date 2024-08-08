package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type Version struct {
	Major    string `json:"major"`
	Minor    string `json:"minor"`
	PlatForm string `json:"platform"`
}

type NodeList struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Items      []Node `json:"items"`
}

type Node struct {
	MetaData NodeMeta   `json:"metadata"`
	Status   NodeStatus `json:"status"`
}

type NodeMeta struct {
	Name              string `json:"name,omitempty"`
	UID               string `json:"uid,omitempty"`
	ResourceVersion   string `json:"resourceVersion,omitempty"`
	CreationTimestamp string `json:"creationTimestamp,omitempty"`
}

type NodeStatus struct {
	Address     []NodeAddress   `json:"addresses,omitempty"`
	Conditions  []NodeCondition `json:"conditions,omitempty"`
	Capacity    ResourceList    `json:"capacity,omitempty"`
	Allocatable ResourceList    `json:"allocatable,omitempty"`
	NodeInfo    NodeInfo        `json:"nodeInfo,omitempty"`
}

type NodeInfo struct {
	MachineID               string `json:"machineID,omitempty"`
	SystemUUID              string `json:"systemUUID,omitempty"`
	BootID                  string `json:"bootID,omitempty"`
	KernelVersion           string `json:"kernelVersion,omitempty"`
	OsImage                 string `json:"osImage,omitempty"`
	ContainerRuntimeVersion string `json:"containerRuntimeVersion,omitempty"`
	KubeletVersion          string `json:"kubeletVersion,omitempty"`
	KubeProxyVersion        string `json:"kubeProxyVersion,omitempty"`
	OperatingSystem         string `json:"operatingSystem,omitempty"`
	Architecture            string `json:"architecture,omitempty"`
}

type ResourceList map[string]string

type NodeAddress struct {
	Type    string `json:"type"`
	Address string `json:"address"`
}

type NodeCondition struct {
	Type   string `json:"type,omitempty"`
	Status string `json:"status,omitempty"`
}

type PodList struct {
	Items []Pod `json:"items"`
}

type Pod struct {
	MetaData PodMeta   `json:"metadata"`
	Status   PodStatus `json:"status"`
	Spec     PodSpec   `json:"spec"`
}

type Metadata struct {
	Annotations *map[string]string
}

type ObjectWithMeta struct {
	Metadata Metadata `json:"metadata"`
}

type PodSpec struct {
	HostNetwork bool           `json:"hostNetwork"`
	Containers  []PodContainer `json:"containers"`
}

type PodContainer struct {
	Ports []PodContainerPort `json:"ports"`
}

type PodContainerPort struct {
	PodIPv4       string
	PodIpv6       string
	Name          string `json:"name"`
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
}
type PodMeta struct {
	Name        string         `json:"name,omitempty"`
	NameSpace   string         `json:"namespace,omitempty"`
	NodeName    string         `json:"nodeName"`
	Annotations PodAnnotations `json:"annotations,omitempty"`
	Labels      PodLabels      `json:"labels,omitempty"`
}

type PodAnnotations map[string]string
type PodLabels map[string]string

type PatchPodReq []PatchPod
type PatchPod struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}
type NetworkInfoList []NetworkInfo
type NetworkInfo struct {
	PortId string   `json:"port_id"`
	SgIds  []string `json:"sg_ids"`
	QosId  string   `json:"qos_id"`
}
type PodStatus struct {
	PodIP  string  `json:"podIP"`
	PodIps []PodIp `json:"podIPs"`
	HostIP string  `json:"hostIp"`
}
type PodIp struct {
	IP string `json:"ip,omitempty"`
}

type EndpointsList struct {
	Items []Endpoint `json:"items"`
}

type Endpoint struct {
	MetaData EndpointMeta     `json:"metadata"`
	Subsets  []EndpointSubset `json:"subsets"`
}

type EndpointMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type EndpointSubset struct {
	Addresses []EndpointAddress `json:"addresses"`
	Ports     []EndpointPort    `json:"ports"`
}

type EndpointAddress struct {
	IP string `json:"ip"`
	//NodeName string `json:"nodeName"`
}

type EndpointPort struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Name     string `json:"name"`
}

type NetworkCrdList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkCrd `json:"items"`
}

type NetworkCrd struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              NetworkCrdSpec `json:"spec"`
}

func (n *NetworkCrd) DeepCopyInto(out *NetworkCrd) {
	*out = *n
	out.TypeMeta = n.TypeMeta
	n.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = n.Spec
	return
}

func (n *NetworkCrd) DeepCopyObject() runtime.Object {
	//TODO implement me
	if n == nil {
		return nil
	}
	out := new(NetworkCrd)
	n.DeepCopyInto(out)
	return out
}

func (n *NetworkCrdList) DeepCopyInto(out *NetworkCrdList) {
	*out = *n
	out.TypeMeta = n.TypeMeta
	n.ListMeta.DeepCopyInto(&out.ListMeta)
	if n.Items != nil {
		in, out := &n.Items, &out.Items
		*out = make([]NetworkCrd, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}
func (n *NetworkCrdList) DeepCopyObject() runtime.Object {
	if n == nil {
		return nil
	}
	out := new(NetworkCrdList)
	n.DeepCopyInto(out)
	return out
}

type NetworkCrdSpec struct {
	CreateAt     string   `json:"create_at"`
	NetworkID    string   `json:"network_id"`
	ReleaseAfter string   `json:"release_after"`
	StaticIP     string   `json:"static_ip"`
	SubNets      []Subnet `json:"subnets"`
	TenantID     string   `json:"tenant_id"`
}

type Subnet struct {
	Cidr       string `json:"cidr"`
	EnableDHCP bool   `json:"enable_dhcp"`
	GatewayIP  string `json:"gateway_ip"`
	IPVersion  int    `json:"ip_version"`
	Name       string `json:"name"`
	SubnetID   string `json:"subnet_id"`
}

type ServiceList struct {
	Kind       string    `json:"kind"`
	ApiVersion string    `json:"apiVersion"`
	Items      []Service `json:"items"`
}

type Service struct {
	MetaData ServiceMetaData `json:"metadata"`
	Spec     ServiceSpec     `json:"spec"`
}

type ServiceRespList struct {
	Kind       string        `json:"kind"`
	ApiVersion string        `json:"apiVersion"`
	Items      []RespService `json:"items"`
}

type RespService struct {
	MetaData ServiceMetaData  `json:"metadata"`
	Spec     ServiceSpec      `json:"spec"`
	Endpoint []EndpointSubset `json:"endpoint"`
}

type ServiceMetaData struct {
	Name              string                `json:"name"`
	NameSpace         string                `json:"namespace"`
	UID               string                `json:"uid,omitempty"`
	ResourceVersion   string                `json:"resourceVersion,omitempty"`
	CreationTimestamp string                `json:"creationTimestamp,omitempty"`
	Labels            ServiceMetaDataLabels `json:"labels,omitempty"`
	Annotations       ServiceMetaDataLabels `json:"annotations,omitempty"`
}

type ServiceMetaDataLabels map[string]string

type ServiceSpec struct {
	Ports                 []ServicePort   `json:"ports"`
	Selector              ServiceSelector `json:"selector,omitempty"`
	ClusterIP             string          `json:"clusterIP,omitempty"`
	Type                  string          `json:"type,omitempty"`
	ExternalTrafficPolicy string          `json:"externalTrafficPolicy,omitempty"`
}

type ServiceSelector map[string]string

type ServicePort struct {
	Name       string      `json:"name,omitempty"`
	Protocol   string      `json:"protocol,omitempty"`
	Port       uint16      `json:"port,omitempty"`
	TargetPort interface{} `json:"targetPort,omitempty"`
	NodePort   uint16      `json:"nodePort,omitempty"`
}
