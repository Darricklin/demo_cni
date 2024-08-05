package etcd

import (
	"encoding/json"
	"errors"
	"fmt"
	clientv3 "go.etcd.io/etcd/client/v3"
	"k8s.io/klog"
)

func OpPutObject(key string, valueObj interface{}, opts ...clientv3.OpOption) (clientv3.Op, error) {
	var op clientv3.Op
	value, err := json.Marshal(valueObj)
	if err != nil {
		errmsg := fmt.Sprintf("failed to encoding %+v", valueObj)
		klog.Error(errmsg)
		return op, errors.New(errmsg)
	}
	return clientv3.OpPut(key, string(value), opts...), nil
}

func OpDelete(key string, opts ...clientv3.OpOption) clientv3.Op {
	return clientv3.OpDelete(key, opts...)
}

func OpPutNode(nodeName string, node Node) (clientv3.Op, error) {
	key := NodeKey(nodeName)
	return OpPutObject(key, node)
}

func OpDeleteNode(nodeName string, node Node) clientv3.Op {
	key := NodeKey(nodeName)
	return OpDelete(key)
}

func OpPutNetwork(name string, network NetworkCrd) (clientv3.Op, error) {
	key := NetworkKey(name)
	return OpPutObject(key, network)
}

func OpDeleteNetwork(name string) clientv3.Op {
	key := NetworkKey(name)
	klog.Errorf("==========network key is %v", key)
	return OpDelete(key)
}
