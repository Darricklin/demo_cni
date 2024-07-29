package etcd

import (
	"context"
	"fmt"
	etcd "go.etcd.io/etcd/client/v3"
	"k8s.io/klog"
	"time"
)

type EtcdMutex struct {
	TTL     int64
	Client  *etcd.Client
	Key     string
	cancel  context.CancelFunc
	lease   etcd.Lease
	leaseId etcd.LeaseID
	txn     etcd.Txn
}

func (em *EtcdMutex) init() error {
	var err error
	var ctx context.Context
	em.txn = etcd.NewKV(em.Client).Txn(context.TODO())
	em.lease = etcd.NewLease(em.Client)
	leaseResp, err := em.lease.Grant(context.TODO(), em.TTL)
	if err != nil {
		return err
	}
	ctx, em.cancel = context.WithCancel(context.Background())
	em.leaseId = leaseResp.ID
	ch, err := em.lease.KeepAlive(ctx, em.leaseId)
	if err != nil {
		return err
	}
	go func() {
		for {
			time.Sleep(10 * time.Second)
			data := <-ch
			if data == nil {
				break
			}
		}
	}()
	return nil
}

func (em *EtcdMutex) Lock() error {
	err := em.init()
	if err != nil {
		return err
	}
	em.txn.If(etcd.Compare(etcd.CreateRevision(em.Key), "=", 0)).Then(etcd.OpPut(em.Key, "lock", etcd.WithLease(em.leaseId))).Else()
	txnResp, err := em.txn.Commit()
	if err != nil {
		return err
	}
	if !txnResp.Succeeded {
		em.Unlock()
		return fmt.Errorf(em.Key + "--get key failed ")
	}
	klog.Infof(em.Key + "--get key succeeded")
	return nil
}

func (em *EtcdMutex) Unlock() {
	em.cancel()
	_, err := em.lease.Revoke(context.TODO(), em.leaseId)
	if err != nil {
		klog.Infof("lock lease revoke : err %s", err.Error())
	}
	err = em.lease.Close()
	if err != nil {
		klog.Infof("lock lease close: err %s", err.Error())
	}
	klog.Infof(em.Key + "--unlock")
}

func NewMutex(key string, client *etcd.Client) (mutex *EtcdMutex) {
	mutex = &EtcdMutex{Client: client, Key: key, TTL: 10}
	return
}
