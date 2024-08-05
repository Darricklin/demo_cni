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
	"strings"
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

	ws.Route(ws.POST(constants.Validate).
		To(func(request *restful.Request, response *restful.Response) { ValidateRequest(nm, request, response) }).
		Doc("validate crd resources").
		Reads(v1beta1.AdmissionReview{}).
		Writes(v1beta1.AdmissionReview{}).
		Returns(http.StatusOK, http.StatusText(http.StatusOK), v1beta1.AdmissionReview{}).
		Returns(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), ErrorResp{}))
	wsContainer.Add(ws)
	tlsCertKey, err := tls.LoadX509KeyPair(nm.TlsCertPath, nm.TlsKeyPath)
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
	go startTLSServer(nm, &http.Server{Handler: wsContainer,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCertKey}}}, listener, "", "")
	klog.Infof("init webhook succeed")
	return nil
}

func startTLSServer(nm *options.MasterAgent, server *http.Server, listener net.Listener, certFile, Keyfile string) {
	defer nm.StopWg.Done()
	stopCh := make(chan struct{})
	go func() {
		if err := server.ServeTLS(listener, certFile, Keyfile); err != nil {
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
	admissionResponse := &v1beta1.AdmissionResponse{}
	admissionResponse.Allowed = isAllowed
	if !isAllowed && errorMessage != "" {
		admissionResponse.Result = &v1.Status{
			Message: errorMessage,
		}
	}
	if ar != nil && ar.Request != nil {
		admissionResponse.UID = ar.Request.UID
	}
	if patch != "" {
		admissionResponse.Patch = []byte(patch)
		pt := v1beta1.PatchTypeJSONPatch
		admissionResponse.PatchType = &pt
	}
	admissionReview := v1beta1.AdmissionReview{Response: admissionResponse}
	if ar != nil && ar.APIVersion != "" && ar.Kind != "" {
		admissionReview.Kind = ar.Kind
		admissionReview.APIVersion = ar.APIVersion
	}
	if err := response.WriteEntity(admissionReview); err != nil {
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
			return fmt.Errorf("network crd is exist")
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
				ipPool := make(map[string]string)
				for ipaddr := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ipaddr); ipam.Inc(ipaddr) {
					ipPool[ipaddr.String()] = "0"
				}
				etcdSub := etcd.Subnet{
					Name:      subnet.Name,
					CIDR:      subnet.Cidr,
					Reserved:  ipPool,
					Allocated: make(map[string]string),
					IpVersion: subnet.IPVersion,
					Gateway:   subnet.GatewayIP,
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
		networkOld, err := nm.K8sAgent.GetNetworkCrd(network.Name)
		if err != nil {
			return err
		}

		if network.Name != networkOld.Name {
			return fmt.Errorf("name cannot change")
		}
		allPodList, err := nm.K8sAgent.GetPodList()
		if err != nil {
			return err
		}
		for _, pod := range allPodList.Items {
			if networkAnno, ok := pod.MetaData.Annotations[constants.NETWORK]; ok {
				networkInfo := strings.Split(networkAnno, "/")
				if len(networkInfo) == 2 {
					if network.Name == networkInfo[1] {
						return fmt.Errorf("network used by pod,cannot update")
					}
				}
			}
		}
		if !reflect.DeepEqual(network.Spec.SubNets, networkOld.Spec.SubNets) {
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
				ipPool := make(map[string]string)
				for ipaddr := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ipaddr); ipam.Inc(ipaddr) {
					ipPool[ipaddr.String()] = "1"
				}
				etcdSub := etcd.Subnet{
					Name:      subnet.Name,
					CIDR:      subnet.Cidr,
					Reserved:  ipPool,
					Allocated: make(map[string]string),
					IpVersion: subnet.IPVersion,
					Gateway:   subnet.GatewayIP,
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
		klog.Errorf("======delete crd %v", network.Name)
		allPodList, err := nm.K8sAgent.GetPodList()
		if err != nil {
			return err
		}
		for _, pod := range allPodList.Items {
			if networkAnno, ok := pod.MetaData.Annotations[constants.NETWORK]; ok {
				networkInfo := strings.Split(networkAnno, "/")
				if len(networkInfo) == 2 {
					if network.Name == networkInfo[1] {
						return fmt.Errorf("network used by pod,cannot delete")
					}
				}
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
	if err := request.ReadEntity(&ar); err != nil {
		klog.Error(err)
		writeValidateResponse(response, false, nil, "", err.Error())
		return
	}
	req := ar.Request
	klog.Infof("AdmissionReview for Kind=%v, NameSpace=%v, Name=%v, UID=%v, patchOperation=%v, UserInfo=%v",
		req.Kind, req.Namespace, req.Name, req.UID, req.Operation, req.UserInfo)
	switch req.Kind.Kind {
	case "NetworkAttachmentDefinition":
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
