package app

import (
	"context"
	"fmt"
	"github.com/cni/cmd/master-agent/app/constants"
	"github.com/cni/cmd/master-agent/app/options"
	"github.com/cni/pkg/util/etcd"
	"github.com/cni/pkg/util/k8s"
	"github.com/emicklei/go-restful/v3"
	clientSet "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
	"net"
	"net/http"
	"time"
)

func RUN(nm *options.MasterAgent) error {
	err := run(nm)
	if err != nil {
		nm.Cancel()
	}
	select {
	case <-nm.Done():
		nm.StopWg.Wait()
		break
	}
	return err
}

func run(nm *options.MasterAgent) error {
	if err := initEtcd(nm); err != nil {
		klog.Errorf("failed to init etcdAgent ,err is %s", err)
		return err
	}
	if err := initK8s(nm); err != nil {
		klog.Errorf("failed to init k8sAgent ,err is %s", err)
		return err
	}
	if err := initServer(nm); err != nil {
		klog.Errorf("failed to init master server app ,err is %s", err)
		return err
	}
	if err := InitWebHook(nm); err != nil {
		klog.Errorf("failed to init webhook app ,err is %s", err)
		return err
	}
	nm.AddReport(func() {
		klog.V(1).Infoln(nm)
	})
	return nil
}
func initEtcd(nm *options.MasterAgent) error {
	klog.Infof("init etcd agent")
	cli, err := etcd.NewClient(nm.EtcdFlags.Flags)
	if err != nil {
		return fmt.Errorf("failed to create etcd client: %s", err)
	}

	nm.EtcdAgent = cli
	klog.Infof("init etcd agent succeed")
	return nil
}
func initK8s(nm *options.MasterAgent) error {
	klog.Infof("init k8s agent")
	k8sAgent, err := k8s.NewClient(nm.K8sFlags.Flags)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %s", err)
	}
	nm.K8sAgent = k8sAgent
	klog.Infof("init k8s agent succeed")
	klog.Infof("init k8s clientSet")
	k8sConfig, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		return fmt.Errorf("failed to build k8s clientSet config: %s", err)
	}
	k8sClientSet, err := clientSet.NewForConfig(k8sConfig)
	if err != nil {
		return fmt.Errorf("failed to build k8s clientSet : %s", err)
	}
	nm.K8sClientSet = k8sClientSet
	klog.Infof("init k8sClientSet succeed")
	return nil
}

func initServer(nm *options.MasterAgent) error {
	klog.Info("init server ")
	wsContainer := restful.NewContainer()
	wsContainer.Router(restful.CurlyRouter{})
	ws := new(restful.WebService)
	ws.Path(constants.Base).Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)
	ws.Route(ws.GET(constants.Health).To(GetHealth(nm)).
		Doc("get server health").
		Writes(HealthResp{}).
		Returns(http.StatusOK, http.StatusText(http.StatusOK), HealthResp{}))
	ws.Route(ws.GET(constants.Version).To(GetVersion(nm)).
		Doc("get server health").
		Writes(VersionResp{}).
		Returns(http.StatusOK, http.StatusText(http.StatusOK), VersionResp{}))
	wsContainer.Add(ws)
	addr := fmt.Sprintf("%s:%s", nm.BindHost, nm.BindPort)
	listenerAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to create listeneraddr %s : %v", listenerAddr, err)
	}
	listener, err := net.ListenTCP("tcp", listenerAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener %s : %v", listenerAddr, err)
	}
	nm.StopWg.Add(1)
	go startServer(nm, &http.Server{Handler: wsContainer}, listener)
	klog.Info("start server succeed")
	return nil
}

type HealthResp struct {
	Health string `json:"health"`
}
type VersionResp struct {
	Version string `json:"version"`
}

func startServer(nm *options.MasterAgent, server *http.Server, listener net.Listener) {
	defer nm.StopWg.Done()
	stopCh := make(chan struct{})
	go func() {
		if err := server.Serve(listener); err != nil {
			klog.Errorf("failed to start server; err is %s", err)
			close(stopCh)
		}
	}()
	select {
	case <-nm.Done():
		klog.Errorf("receive nm Done,shut down master server")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := server.Shutdown(ctx); err != nil {
			klog.Errorf("failed to shutdown server; err is %s", err)
		}
		cancel()
		<-stopCh
		break
	case <-stopCh:
		nm.Cancel()
		break
	}
}
func GetHealth(_ *options.MasterAgent) func(request *restful.Request, response *restful.Response) {
	return func(request *restful.Request, response *restful.Response) {
		health := HealthResp{Health: "ok"}
		if err := response.WriteEntity(health); err != nil {
			klog.Error(err)
		}
	}
}
func GetVersion(_ *options.MasterAgent) func(request *restful.Request, response *restful.Response) {
	return func(request *restful.Request, response *restful.Response) {
		version := VersionResp{
			Version: "v1.0",
		}
		if err := response.WriteEntity(version); err != nil {
			klog.Error(err)
		}
	}
}
