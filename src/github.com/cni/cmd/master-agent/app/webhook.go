package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/cni/cmd/master-agent/app/constants"
	"github.com/cni/cmd/master-agent/app/options"
	"github.com/cni/pkg/util/etcd"
	"github.com/cni/pkg/util/ipam"
	"github.com/cni/pkg/util/k8s"
	"github.com/emicklei/go-restful"
	clientv3 "go.etcd.io/etcd/client/v3"
	"k8s.io/api/admission/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"net"
	"net/http"
	"reflect"
	"time"
)

type ErrorResp struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func InitWebHook(nm *options.MasterAgent) error {
	klog.Infof("initializing webhook server")
	wsContainer := restful.NewContainer()
	wsContainer.Router(restful.CurlyRouter{})
	ws := new(restful.WebService)
	ws.Path(constants.Base).Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)

	ws.Route(ws.POST(constants.Validate).To(func(request *restful.Request, response *restful.Response) {
		ValidateRequest(nm, request, response)
	}).Returns(http.StatusOK, http.StatusText(http.StatusOK), v1beta1.AdmissionReview{}).
		Returns(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), ErrorResp{}))
	wsContainer.Add(ws)
	tlsCertKey, err := tls.LoadX509KeyPair(nm.CertPath, nm.KeyPath)
	if err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%s", nm.BindHost, nm.WebHookBindPort)
	listenAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return err
	}
	nm.StopWg.Add(1)
	go startTLSServer(nm, &http.Server{Handler: wsContainer, TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCertKey}}}, listener)
	return nil
}

func startTLSServer(nm *options.MasterAgent, server *http.Server, listener net.Listener) {
	defer nm.StopWg.Done()
	stopCh := make(chan struct{})
	go func() {
		if err := server.ServeTLS(listener, nm.CertPath, nm.KeyPath); err != nil {
			klog.Error(err)
			close(stopCh)
		}
	}()
	select {
	case <-nm.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := server.Shutdown(ctx); err != nil {
			klog.Error(err)
		}
		cancel()
		<-stopCh
		break
	case <-stopCh:
		nm.Cancel()
		break
	}
}
func writeValidateResponse(response *restful.Response, isAllowed bool, ar *v1beta1.AdmissionReview, patch string, errorMessage string) {
	adminssionResponse := &v1beta1.AdmissionResponse{}
	adminssionResponse.Allowed = isAllowed
	if !isAllowed && errorMessage != "" {
		adminssionResponse.Result = &v1.Status{
			Message: errorMessage,
		}
	}
	if ar != nil && ar.Request != nil {
		adminssionResponse.UID = ar.Request.UID
	}
	if patch != "" {
		adminssionResponse.Patch = []byte(patch)
		pt := v1beta1.PatchTypeJSONPatch
		adminssionResponse.PatchType = &pt
	}
	adminssionReview := v1beta1.AdmissionReview{Response: adminssionResponse}
	if ar != nil && ar.APIVersion != "" && ar.Kind != "" {
		adminssionReview.Kind = ar.Kind
		adminssionReview.APIVersion = ar.APIVersion
	}
	if err := response.WriteEntity(adminssionReview); err != nil {
		klog.Error(err)
	}
}

func validateNetwork(nm *options.MasterAgent, request *v1beta1.AdmissionRequest) error {
	var network k8s.NetworkCrd

	if len(request.Object.Raw) > 0 {
		if err := json.Unmarshal(request.Object.Raw, &network); err != nil {
			klog.Errorf("cannot unmarshal raw object ")
			return err
		}
	}
	switch request.Operation {
	case v1beta1.Create:
		if _, err := nm.K8sAgent.GetNetworkCrd(network.Name); err == nil {
			return fmt.Errorf("exists")
		} else {
			var ops []clientv3.Op
			ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
			txn := nm.EtcdAgent.Client.Txn(ctx)
			networkCrdETCDData := etcd.NetworkCrd{
				Name:    network.Name,
				Subnets: []etcd.Subnet{},
			}
			for _, subnet := range network.Spec.SubNets {
				_, ipNet, err := net.ParseCIDR(subnet.Cidr)
				if err != nil {
					return err
				}
				ippool := make(map[string]string)
				for ipaddr := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ipaddr); ipam.Inc(ipaddr) {
					ippool[ipaddr.String()] = "0"
				}
				etcdSub := etcd.Subnet{
					Name:         subnet.Name,
					CIDR:         subnet.Cidr,
					AllocatedIps: ippool,
					IpVersion:    subnet.IPVersion,
					Gateway:      subnet.GatewayIP,
				}
				networkCrdETCDData.Subnets = append(networkCrdETCDData.Subnets, etcdSub)
			}
			op, err := etcd.OpPutNetwork(network.Name, networkCrdETCDData)
			if err != nil {
				return err
			}
			ops = append(ops, op)
			if len(ops) > 0 {
				if _, err := txn.Then(ops...).Commit(); err != nil {
					return err
				}
			}
		}
		return nil
	case v1beta1.Update:
		if len(request.Object.Raw) > 0 {
			if err := json.Unmarshal(request.Object.Raw, &network); err != nil {
				klog.Errorf("cannot unmarshal raw object ")
				return err
			}
		}
		networkold, err := nm.K8sAgent.GetNetworkCrd(network.Name)
		if err != nil {
			return err
		}
		// TODO 如果有pod使用crd，不允许更新
		if network.Name != networkold.Name {
			return fmt.Errorf("name cannot change")
		}
		if !reflect.DeepEqual(network.Spec.SubNets, networkold.Spec.SubNets) {
			var ops []clientv3.Op
			ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
			txn := nm.EtcdAgent.Client.Txn(ctx)
			networkCrdETCDData := etcd.NetworkCrd{
				Name:    network.Name,
				Subnets: []etcd.Subnet{},
			}
			for _, subnet := range network.Spec.SubNets {
				_, ipNet, err := net.ParseCIDR(subnet.Cidr)
				if err != nil {
					return err
				}
				ippool := make(map[string]string)
				for ipaddr := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ipaddr); ipam.Inc(ipaddr) {
					ippool[ipaddr.String()] = "0"
				}
				etcdSub := etcd.Subnet{
					Name:         subnet.Name,
					CIDR:         subnet.Cidr,
					AllocatedIps: ippool,
					IpVersion:    subnet.IPVersion,
					Gateway:      subnet.GatewayIP,
				}
				networkCrdETCDData.Subnets = append(networkCrdETCDData.Subnets, etcdSub)
			}
			op, err := etcd.OpPutNetwork(network.Name, networkCrdETCDData)
			if err != nil {
				return err
			}
			ops = append(ops, op)
			if len(ops) > 0 {
				if _, err := txn.Then(ops...).Commit(); err != nil {
					return err
				}
			}
			return nil
		}
	case v1beta1.Delete:
		// TODO 如果有pod使用crd，不允许删除
		if len(request.Object.Raw) > 0 {
			if err := json.Unmarshal(request.Object.Raw, &network); err != nil {
				klog.Errorf("cannot unmarshal raw object ")
				return err
			}
		}
		var ops []clientv3.Op
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		txn := nm.EtcdAgent.Client.Txn(ctx)
		op := etcd.OpDeleteNetwork(network.Name)
		ops = append(ops, op)
		if len(ops) > 0 {
			if _, err := txn.Then(ops...).Commit(); err != nil {
				return err
			}
		}
	}
	return nil
}
func ValidateRequest(nm *options.MasterAgent, request *restful.Request, response *restful.Response) {
	var ar v1beta1.AdmissionReview
	if err := request.ReadEntity(ar); err != nil {
		klog.Error(err)
		writeValidateResponse(response, false, nil, "", err.Error())
		return
	}
	req := ar.Request
	klog.Infof("AdmissionReview for Kind=%v, NameSpace=%v, Name=%v, UID=%v, patchOperation=%v, UserInfo=%v",
		req.Kind, req.Namespace, req.Name, req.UID, req.Operation, req.UserInfo)
	switch req.Kind.Kind {
	case "Network":
		err := validateNetwork(nm, req)
		if err != nil {
			klog.Error(err)
			writeValidateResponse(response, false, &ar, "", err.Error())
			return
		}
		writeValidateResponse(response, true, &ar, "", "")
	default:
		writeValidateResponse(response, false, &ar, "", "unknown resource type")
	}
}
