package controllers

import (
	"context"
	"fmt"
	"github.com/cni/cmd/node-agent/app/options"
	"github.com/cni/pkg/util/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
)

const (
	GROUP    = "k8s.cni.cncf.io"
	Version  = "v1"
	Resource = "network-attachment-definitions"
	APIPath  = "/apis"
)

func (nc *NetworkCrdController) addCRD(obj interface{}) {
	crd := obj.(*k8s.NetworkCrd)
	fmt.Printf("add crd %+v\n", crd)
}

func (nc *NetworkCrdController) updateCrd(oldObj, newObj interface{}) {
	if !nc.IsSynced() {
		klog.Infof("network controller not synced")
		return
	}
	oldCrd := oldObj.(*k8s.NetworkCrd)
	newCrd := newObj.(*k8s.NetworkCrd)
	fmt.Printf("update crd %s\n", oldCrd.Name)
	fmt.Printf("new crd is %+v\n", newCrd)
}

func (nc *NetworkCrdController) deleteCrd(obj interface{}) {
	if !nc.IsSynced() {
		klog.Infof("network controller not synced")
		return
	}
	crd := obj.(*k8s.NetworkCrd)
	fmt.Printf("delete crd %+v\n", crd)
}

func AddToScheme(scheme *runtime.Scheme) {
	scheme.AddKnownTypes(schema.GroupVersion{Group: "k8s.cni.cncf.io", Version: "v1"}, &k8s.NetworkCrd{}, &k8s.NetworkCrdList{})
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Group: "k8s.cni.cncf.io", Version: "v1"})
}

type NetworkCrdController struct {
	informer cache.Controller
	indexer  cache.Indexer
	ctx      context.Context
	na       *options.NodeAgent
	isSynced bool
}

func NewNetWorkCrdController(na *options.NodeAgent) *NetworkCrdController {
	networkCrdController := &NetworkCrdController{
		informer: nil,
		indexer:  nil,
		ctx:      na.Context,
		na:       na,
		isSynced: false,
	}
	configFile := "admin.conf"
	config, err := clientcmd.BuildConfigFromFlags("", configFile)
	if err != nil {
		return networkCrdController
	}
	_, err = kubernetes.NewForConfig(config)
	if err != nil {
		return networkCrdController
	}
	scheme := runtime.NewScheme()
	AddToScheme(scheme)
	restClient, err := rest.RESTClientFor(&rest.Config{
		Host:    config.Host,
		APIPath: APIPath,
		ContentConfig: rest.ContentConfig{GroupVersion: &schema.GroupVersion{Group: GROUP, Version: Version},
			NegotiatedSerializer: serializer.NewCodecFactory(scheme).WithoutConversion()},
		Username:    config.Username,
		Password:    config.Password,
		BearerToken: config.BearerToken,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure:   config.Insecure,
			ServerName: config.ServerName,
			CertData:   config.TLSClientConfig.CertData,
			KeyData:    config.TLSClientConfig.KeyData,
			CAData:     config.TLSClientConfig.CAData,
		},
	})
	if err != nil {
		return networkCrdController
	}
	resource := schema.GroupVersionResource{Group: GROUP, Version: Version, Resource: Resource}
	listWatcher := cache.NewListWatchFromClient(restClient, resource.Resource, metav1.NamespaceAll, fields.Everything())

	indexer, informer := cache.NewIndexerInformer(listWatcher, &k8s.NetworkCrd{}, 0,
		cache.ResourceEventHandlerFuncs{AddFunc: networkCrdController.addCRD,
			UpdateFunc: networkCrdController.updateCrd, DeleteFunc: networkCrdController.deleteCrd}, cache.Indexers{})
	networkCrdController.indexer = indexer
	networkCrdController.informer = informer

	stopCh := make(chan struct{})
	defer close(stopCh)
	go informer.Run(stopCh)
	if !cache.WaitForCacheSync(stopCh, informer.HasSynced) {
		fmt.Println("timeout waiting for caches to sync")
		return networkCrdController
	}
	return networkCrdController
}

func (nc *NetworkCrdController) GetStore() cache.Indexer {
	return nc.indexer
}

func (nc *NetworkCrdController) Run(stopCh chan struct{}) {
	go nc.informer.Run(stopCh)
	for !nc.informer.HasSynced() {

	}
	nc.isSynced = true
	klog.Infof("networkCrdController init over")
	<-stopCh
}
func (nc *NetworkCrdController) IsSynced() bool {
	return nc.isSynced
}
