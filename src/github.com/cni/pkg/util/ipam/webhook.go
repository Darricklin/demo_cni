package ipam

import (
	"cni/utils/k8s"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/emicklei/go-restful"
	"k8s.io/api/admission/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"
)

type ErrorResp struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Webhook struct {
	context.Context
	Cancel   context.CancelFunc
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
	Host     string `json:"host"`
	BindPort string `json:"bind_port"`
	Wg       sync.WaitGroup
}

func (wb *Webhook) InitWebHook() error {
	klog.Infof("initializing webhook server")
	wsContainer := restful.NewContainer()
	wsContainer.Router(restful.CurlyRouter{})
	ws := new(restful.WebService)
	ws.Path("/v1.0").Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)

	ws.Route(ws.GET("/validate").To(ValidateRequest).Returns(http.StatusOK, http.StatusText(http.StatusOK), v1beta1.AdmissionReview{}).
		Returns(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), ErrorResp{}))
	wsContainer.Add(ws)
	tlsCertKey, err := tls.LoadX509KeyPair(wb.CertPath, wb.KeyPath)
	if err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%s", wb.Host, wb.BindPort)
	listenAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return err
	}
	wb.Wg.Add(1)
	go startTLSServer(wb, &http.Server{Handler: wsContainer, TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCertKey}}}, listener)
	return nil
}

func startTLSServer(wb *Webhook, server *http.Server, listener net.Listener) {
	defer wb.Wg.Done()
	stopCh := make(chan struct{})
	go func() {
		if err := server.ServeTLS(listener, wb.CertPath, wb.KeyPath); err != nil {
			klog.Error(err)
			close(stopCh)
		}
	}()
	select {
	case <-wb.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := server.Shutdown(ctx); err != nil {
			klog.Error(err)
		}
		cancel()
		<-stopCh
		break
	case <-stopCh:
		wb.Cancel()
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
func validateNetwork(request *v1beta1.AdmissionRequest) (string, error) {
	var network, networkold k8s.NetworkCrd

	if len(request.Object.Raw) > 0 {
		if err := json.Unmarshal(request.Object.Raw, &network); err != nil {
			klog.Errorf("cannot unmarshal raw object ")
			return "", err
		}
	}
	switch request.Operation {
	case v1beta1.Create:
		for _, subnet := range network.Spec.Subnets {
			if subnet.AllocatedIps != nil {
				klog.Error("new network cannot has AllocatedIps")
				return "", errors.New("new network cannot has AllocatedIps")
			}
			subnet.AllocatedIps = make(map[string]string)
		}
		subnets, err := json.Marshal(network.Spec.Subnets)
		if err != nil {
			klog.Error(err)
		}
		patch := fmt.Sprintf(`[{"op": "replace", "path": "/spec/subnets", "value": %s}]`, subnets)
		return patch, nil
	case v1beta1.Update:
		if len(request.Object.Raw) > 0 {
			if err := json.Unmarshal(request.Object.Raw, &networkold); err != nil {
				klog.Errorf("cannot unmarshal raw object ")
				return "", err
			}
		}
		if !reflect.DeepEqual(network.Spec.Subnets, networkold.Spec.Subnets) {
			for _, subnet := range networkold.Spec.Subnets {
				if subnet.AllocatedIps != nil && len(subnet.AllocatedIps) != 0 {
					return "", errors.New(" network subnets cannot update")
				}
			}
			for _, subnet := range network.Spec.Subnets {
				if subnet.AllocatedIps != nil {
					klog.Error("new network cannot has AllocatedIps")
					return "", errors.New("new network cannot has AllocatedIps")
				}
				subnet.AllocatedIps = make(map[string]string)
			}
			subnets, err := json.Marshal(network.Spec.Subnets)
			if err != nil {
				klog.Error(err)
			}
			patch := fmt.Sprintf(`[{"op": "replace", "path": "/spec/subnets", "value": %s}]`, subnets)
			return patch, nil
		}
	case v1beta1.Delete:
		if len(request.Object.Raw) > 0 {
			if err := json.Unmarshal(request.Object.Raw, &networkold); err != nil {
				klog.Errorf("cannot unmarshal raw object ")
				return "", err
			}
		}
		for _, subnet := range networkold.Spec.Subnets {
			if subnet.AllocatedIps != nil && len(subnet.AllocatedIps) != 0 {
				return "", errors.New(" network subnets cannot be deleted")
			}
		}
	}
	return "", nil
}
func ValidateRequest(request *restful.Request, response *restful.Response) {
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
		patch, err := validateNetwork(req)
		if err != nil {
			klog.Error(err)
			writeValidateResponse(response, false, &ar, "", err.Error())
			return
		}
		writeValidateResponse(response, true, &ar, patch, "")
	default:
		writeValidateResponse(response, false, &ar, "", "unknown resource type")
	}
}
