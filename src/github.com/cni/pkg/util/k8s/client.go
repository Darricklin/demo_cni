package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/cni/pkg/util/rest"
	"github.com/emicklei/go-restful/v3"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"net/http"
	"strings"
)

type Client struct {
	*rest.Client
	Token string
}

func NewClient(conf *Flags) (*Client, error) {
	if strings.HasPrefix(conf.K8sApiServer, "https") {
		token := ""
		ca, err := ioutil.ReadFile(conf.K8sCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read k8s ca file: %v", err)
		}
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(ca)
		tlsCfg := &tls.Config{RootCAs: caPool}
		cert, err := tls.LoadX509KeyPair(conf.K8sCert, conf.K8sKey)
		if err != nil {
			if conf.K8sToken == "" {
				return nil, fmt.Errorf("failed to load the client certificates and missing auth token :%v", err)
			}
			token = conf.K8sToken
		} else {
			tlsCfg.Certificates = []tls.Certificate{cert}
			tlsCfg.BuildNameToCertificate()
		}
		transport := &http.Transport{TLSClientConfig: tlsCfg}
		client := &http.Client{Transport: transport}
		c := &Client{Client: rest.NewClient(client, conf.K8sApiServer), Token: token}
		return c, nil
	} else if strings.HasPrefix(conf.K8sApiServer, "http") {
		c := &Client{Client: rest.NewClient(http.DefaultClient, conf.K8sApiServer)}
		return c, nil
	} else {
		return nil, fmt.Errorf("only http or https is supported ofr apiserver,get %s", conf.K8sApiServer)
	}
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Content-Type", restful.MIME_JSON)
	req.Header.Set("Accept", restful.MIME_JSON)
	if c.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.Token))
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) CheckResponse(method string, path string, body interface{}, resp *http.Response) (*http.Response, error) {
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return resp, rest.NewBadResponseError(method, path, body, http.StatusText(resp.StatusCode))
	}
	return resp, nil
}
func (c *Client) Request(method string, path string, body interface{}, respObj interface{}) (int, error) {
	return rest.Request(c, method, path, body, respObj)
}

func (c *Client) GetVersion() (Version, error) {
	var ver Version
	if code, err := c.Request("GET", "/version", nil, &ver); err != nil {
		klog.Errorf("failed to get k8s version ,code %v, error is %v", code, err)
		return ver, fmt.Errorf("failed to get k8s apiserver version: %v", err)
	}
	klog.Infof("get k8s version : %v ", ver)
	return ver, nil
}

func (c *Client) GetNodeList(req *restful.Request, resp *restful.Response) {
	var nodeList, nodeListResp NodeList

	code, err := c.Request("GET", "/api/v1/nodes", nil, &nodeList)
	if err != nil {
		klog.Errorf("failed to get k8s nodes ,code %v, error is %v", code, err)
		rest.WriteError(resp, http.StatusInternalServerError, rest.StatusInternalServerError, err.Error())
		return
	}
	klog.Infof("get k8s nodes : %+v , code : %v", nodeList, code)
	nodeListResp = NodeList{
		Kind:       nodeList.Kind,
		APIVersion: nodeList.APIVersion,
		Items:      []Node{},
	}
	for _, node := range nodeList.Items {
		var conditions []NodeCondition
		for _, condition := range node.Status.Conditions {
			if condition.Type == "Ready" {
				conditions = append(conditions, condition)
				break
			}
		}
		node.Status.Conditions = conditions
		nodeListResp.Items = append(nodeListResp.Items, node)
		klog.Infof("node condition is %+v", node.Status.Conditions)
	}
	_ = resp.WriteAsJson(nodeListResp)
	return
}

func (c *Client) GetPodAnnoAndLabels(ns, name string) (PodLabels, PodAnnotations, string, error) {
	podUrl := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", ns, name)
	var pod Pod
	if _, err := c.Request("GET", podUrl, nil, &pod); err != nil {
		return nil, nil, "", err
	}
	return pod.MetaData.Labels, pod.MetaData.Annotations, pod.Status.PodIP, nil
}

func (c *Client) GetPodList() (PodList, error) {
	var podList PodList

	code, err := c.Request("GET", "/api/v1/pods", nil, &podList)
	if err != nil {
		klog.Errorf("failed to get k8s pods ,code %v, error is %v", code, err)
		return podList, err
	}
	podListResp := PodList{
		Kind:       podList.Kind,
		APIVersion: podList.APIVersion,
		Items:      []Pod{},
	}
	for _, pod := range podList.Items {
		if pod.Status.Phase == "Running" {
			podListResp.Items = append(podListResp.Items, pod)
		}
	}
	klog.Infof("get k8s pods : %+v , code : %v", podList, code)
	return podList, nil
}

func (c *Client) UpdatePod(req *restful.Request, resp *restful.Response) {
	nameSpace := req.HeaderParameter("namespace")
	podName := req.HeaderParameter("podname")
	klog.Infof("namespace is [%s]", nameSpace)
	//networkInfo := req.HeaderParameter("networkinfo")
	//klog.Infof("namespace is [%s], pod is [%s], networkInfo is [%s]", nameSpace, podName, networkInfo)
	k8sconfig, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		klog.Errorf("failed to make k8s config , error is %v", err)
		return
	}
	k8sclient, err := clientset.NewForConfig(k8sconfig)
	if err != nil {
		klog.Errorf("failed to make k8s client , error is %v", err)
		return
	}
	pod_in, err := k8sclient.CoreV1().Pods(nameSpace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		klog.Errorf("failed to get pod,err is %s", err)
		return
	}
	nl := NetworkInfoList{}
	ni1 := NetworkInfo{
		PortId: "asdasgfdsgd",
		SgIds:  []string{"asdjhagfjhagf", "ahgfdkjhagfij"},
		QosId:  "ajhsfdkiajgsfoiuof",
	}
	ni2 := NetworkInfo{
		PortId: "abbbbbbbbbbbbbbbb",
		SgIds:  []string{"abbbbbbbbb", "abbbbbbbbbbb"},
		QosId:  "abbbbbbbbbbbbbbbb",
	}
	nl = append(nl, ni1, ni2)
	nlStr, err := json.Marshal(nl)
	if err != nil {
		klog.Errorf("failed to marshal nl %v, err is %s", nl, err)
	}
	klog.Infof("namespace is [%s], pod is [%s], networkInfo is [%s]", nameSpace, podName, nl)
	var value interface{}
	var patchPod PatchPod
	klog.Infof("pod Annotations is : [ %+v ],equal nil : %v", pod_in.Annotations, pod_in.Annotations == nil)
	if pod_in.Annotations == nil {
		value = map[string]interface{}{ValuePath: nl}
		patchPod = PatchPod{
			Op:    AddOption,
			Path:  BasePath,
			Value: value,
		}
	} else {
		value = string(nlStr)
		patchPod = PatchPod{
			Op:    AddOption,
			Path:  AbsolutePath,
			Value: nl,
		}
	}
	patchpodReq := []PatchPod{patchPod}
	patchdata, err := json.Marshal(patchpodReq)
	if err != nil {
		klog.Errorf("json patch pod failed ,err is %s", err)
	}
	klog.Infof("patchdata is %s", patchdata)
	pod_out, err := k8sclient.CoreV1().Pods(nameSpace).Patch(context.Background(), podName, types.JSONPatchType, patchdata, metav1.PatchOptions{})
	if err != nil {
		klog.Errorf("failed to patch pod ,err is %s", err)
		return
	}
	klog.Infof("update k8s pods : %+v ", pod_out)
	_ = resp.WriteAsJson(pod_out)
	return
}

func (c *Client) GetEndPointList(req *restful.Request, resp *restful.Response) {
	var endpointsList EndpointsList
	code, err := c.Request("GET", "/api/v1/endpoints", nil, &endpointsList)
	if err != nil {
		klog.Errorf("failed to get k8s endpoints ,code %v, error is %v", code, err)
		rest.WriteError(resp, http.StatusInternalServerError, rest.StatusInternalServerError, err.Error())
		return
	}
	klog.Infof("get k8s endpoints : %+v , code : %v", endpointsList, code)
	_ = resp.WriteAsJson(endpointsList)
	return
}
func (c *Client) GetServiceList(req *restful.Request, resp *restful.Response) {
	serviceRespList := ServiceRespList{}
	var serviceList ServiceList
	code, err := c.Request("GET", "/api/v1/services", nil, &serviceList)
	if err != nil {
		klog.Errorf("failed to get k8s services ,code %v, error is %v", code, err)
		rest.WriteError(resp, http.StatusInternalServerError, rest.StatusInternalServerError, err.Error())
		return
	}
	klog.Infof("get k8s services : %+v , code : %v", serviceList, code)
	var endpointsList EndpointsList
	code, err = c.Request("GET", "/api/v1/endpoints", nil, &endpointsList)
	if err != nil {
		klog.Errorf("failed to get k8s endpoints ,code %v, error is %v", code, err)
		rest.WriteError(resp, http.StatusInternalServerError, rest.StatusInternalServerError, err.Error())
		return
	}
	klog.Infof("get k8s endpoints : %+v , code : %v", endpointsList, code)
	serviceRespList.Kind = serviceList.Kind
	serviceRespList.ApiVersion = serviceList.ApiVersion
	for _, service := range serviceList.Items {
		for _, endpoint := range endpointsList.Items {
			if service.MetaData.Name == endpoint.MetaData.Name && service.MetaData.NameSpace == endpoint.MetaData.Namespace {
				respService := RespService{
					MetaData: service.MetaData,
					Spec:     service.Spec,
					Endpoint: endpoint.Subsets,
				}
				serviceRespList.Items = append(serviceRespList.Items, respService)
			}
		}
	}
	_ = resp.WriteAsJson(serviceRespList)
	return
}
func (c *Client) GetNetworkCrdList(req *restful.Request, resp *restful.Response) {
	var networkCrdList NetworkCrdList
	code, err := c.Request("GET", "/apis/k8s.cni.cncf.io/v1/network-attachment-definitions", nil, &networkCrdList)
	if err != nil {
		klog.Errorf("failed to get k8s networkCrd ,code %v, error is %v", code, err)
		rest.WriteError(resp, http.StatusInternalServerError, rest.StatusInternalServerError, err.Error())
		return
	}
	klog.Infof("get k8s networkCrd : %+v , code : %v", networkCrdList, code)
	_ = resp.WriteAsJson(networkCrdList)
	return
}

func (c *Client) GetNetworkCrd(name string) (NetworkCrd, error) {
	var networkCrd NetworkCrd
	url := fmt.Sprintf("/apis/k8s.cni.cncf.io/v1/network-attachment-definitions/%s", name)
	code, err := c.Request("GET", url, nil, &networkCrd)
	if err != nil {
		klog.Errorf("failed to get k8s networkCrd ,code %v, error is %v", code, err)
		return networkCrd, err
	}
	klog.Infof("get k8s networkCrd : %+v , code : %v", networkCrd, code)
	return networkCrd, nil
}
