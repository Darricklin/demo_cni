package etcd

import "fmt"

func NodesKey() string {
	return fmt.Sprintf("%s%s/", CniPrefix, NodesKeyName)
}

func NodeKey(nodeName string) string {
	return fmt.Sprintf("%s%s", NodesKey(), nodeName)
}

func NetworksKey() string {
	return fmt.Sprintf("%s%s/", CniPrefix, NetworksKeyName)
}

func NetworkKey(networkName string) string {
	return fmt.Sprintf("%s%s", NetworksKey(), networkName)
}

func PodsKey() string {
	return fmt.Sprintf("%s%s/", CniPrefix, PodsKeyName)
}

func PodKey(nameSpace, podName string) string {
	return fmt.Sprintf("%s%s/%s", PodsKey, nameSpace, podName)
}
