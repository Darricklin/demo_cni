package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	clientv3 "go.etcd.io/etcd/client/v3"
	"k8s.io/klog"
	"strings"
	"time"
)

func (c *Client) GetObject(key string, obj interface{}, opts ...clientv3.OpOption) (int64, error) {
	ctxt, _ := context.WithTimeout(context.Background(), 3*time.Second)
	resp, err := c.Client.Get(ctxt, key, opts...)
	if err != nil {
		return 0, fmt.Errorf("failed to get key %s from etcd,err [%s]", key, err.Error())
	}
	if resp.Count == 0 {
		return 0, nil
	}
	if err := json.Unmarshal(resp.Kvs[0].Value, obj); err != nil {
		return resp.Count, err
	}
	return resp.Count, nil
}

func (c *Client) GetNodes() (map[string]Node, error) {
	nodeMap := make(map[string]Node)
	key := NodesKey()
	ctxt, _ := context.WithTimeout(context.Background(), 3*time.Second)
	resp, err := c.Client.Get(ctxt, key, clientv3.WithPrefix())
	if err != nil {
		return nodeMap, err
	}
	for _, kv := range resp.Kvs {
		var node Node
		if err := json.Unmarshal(kv.Value, &node); err != nil {
			klog.Error(err)
		}
		nodeName := strings.TrimPrefix(string(kv.Key), key)
		nodeMap[nodeName] = node
	}
	return nodeMap, nil
}

func (c *Client) GetNode(name string) (Node, error) {
	var node Node
	key := NodeKey(name)
	count, err := c.GetObject(key, &node)
	if err != nil {
		return node, err
	}
	if count == 0 {
		return node, fmt.Errorf("node %s not found in etcd", name)
	}
	return node, nil
}

func (c *Client) GetNetworks() (map[string]NetworkCrd, error) {
	networkMap := make(map[string]NetworkCrd)
	key := NetworksKey()
	ctxt, _ := context.WithTimeout(context.Background(), 3*time.Second)
	resp, err := c.Client.Get(ctxt, key, clientv3.WithPrefix())
	if err != nil {
		return networkMap, err
	}
	for _, kv := range resp.Kvs {
		var network NetworkCrd
		if err := json.Unmarshal(kv.Value, &network); err != nil {
			klog.Error(err)
		}
		networkName := strings.TrimPrefix(string(kv.Key), key)
		networkMap[networkName] = network
	}
	return networkMap, nil
}

func (c *Client) GetNetwork(name string) (NetworkCrd, error) {
	var network NetworkCrd
	key := NetworkKey(name)
	count, err := c.GetObject(key, &network)
	if err != nil {
		return network, err
	}
	if count == 0 {
		return network, fmt.Errorf("network %s not found in etcd", name)
	}
	return network, nil
}

func (c *Client) GetPods() (map[string]Pod, error) {
	pods := make(map[string]Pod)
	key := PodsKey()
	ctxt, _ := context.WithTimeout(context.Background(), 3*time.Second)
	resp, err := c.Client.Get(ctxt, key, clientv3.WithPrefix())
	if err != nil {
		return pods, err
	}
	for _, kv := range resp.Kvs {
		var pod Pod
		if err = json.Unmarshal(kv.Value, &pod); err != nil {
			klog.Error(err)
		}
		podName := strings.TrimPrefix(string(kv.Key), key)
		pods[podName] = pod
	}
	return pods, nil
}

func (c *Client) GetPod(ns, name string) (Pod, error) {
	var pod Pod
	key := PodKey(ns, name)
	count, err := c.GetObject(key, &pod)
	if err != nil {
		klog.Error(err)
		return pod, err
	}
	if count == 0 {
		return pod, fmt.Errorf("pod %s not found in etcd", name)
	}
	return pod, nil

}
