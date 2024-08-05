package main

import (
	"encoding/json"
	"fmt"
	"github.com/cni/cmd/node-agent/app"
	"github.com/cni/cmd/node-agent/app/constants"
	"github.com/cni/pkg/util/rest"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"log"
	"os"
	"runtime"
	"strings"
)

func init() {
	runtime.LockOSThread()
}

type NetConf struct {
	types.NetConf
	MTU     int    `json:"mtu"`
	LogFile string `json:"logfile"`
}

func loadNetconf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, nil
}
func openLogFile(logfile string) (*os.File, error) {
	return os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
}

var logger = log.New(os.Stderr, "", log.LstdFlags)

func logError(v ...interface{}) {
	logger.Printf("ERROR %s", fmt.Sprintln(v))
}
func logErrorf(format string, v ...interface{}) error {
	err := fmt.Errorf(format, v...)
	logError(err)
	return err
}

func logInfo(v ...interface{}) {
	logger.Printf("INFO %s", fmt.Sprintln(v...))
}

func logInfof(format string, v ...interface{}) {
	logInfo(fmt.Sprintf(format, v...))
}

func argsString2Map(args string) (map[string]string, error) {
	argsMap := make(map[string]string)
	pairs := strings.Split(args, ";")
	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		if len(kv) != 2 {
			return nil, fmt.Errorf("ARGS:invalid pair %q", pair)
		}
		keyString := kv[0]
		valueString := kv[1]
		argsMap[keyString] = valueString
	}
	return argsMap, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	n, err := loadNetconf(args.StdinData)
	if err != nil {
		return err
	}
	f, err := openLogFile(n.LogFile)
	defer f.Close()
	logger.SetOutput(f)
	argsMap, err := argsString2Map(args.Args)
	if err != nil {
		logError(err)
		return err
	}
	podNamespace := argsMap["K8S_POD_NAMESPACE"]
	podName := argsMap["K8S_POD_NAME"]
	if podNamespace == "" || podName == "" {
		return logErrorf("required CNI variable missing")
	}

	logInfof("receive pod creation event: namespace %s,pod %s,ns %s,containerID %s", podNamespace, podName, args.Netns, args.ContainerID)
	result := types100.Result{
		CNIVersion: n.CNIVersion,
		DNS:        n.DNS,
	}
	pod := app.Pod{
		Name:        podName,
		Namespace:   podNamespace,
		ContainerId: args.ContainerID,
		NetNs:       args.Netns,
		IfName:      args.IfName,
		MTU:         n.MTU,
		Result:      result,
	}
	logInfof("create pod to agent req: %v", pod)
	podResp, err := createPod(pod)
	if err != nil {
		return logErrorf("failed to create pod: %v", err)
	}
	result = podResp.Result
	logInfof("create pod result : %+v", result)
	tempErr := types.PrintResult(&result, result.CNIVersion)
	if tempErr != nil {
		logErrorf("create result %s", tempErr)
	}
	return tempErr
}

func createPod(pod app.Pod) (app.PodResponse, error) {
	client := rest.NewClient(rest.NewHttpClientUnix(constants.NodeAgentSock), "http://unix")

	url := fmt.Sprintf("%s%s", constants.Base, constants.Ports)
	var result app.PodResponse
	logInfof("send pod creation request : %+v", pod)
	if _, err := client.Request("POST", url, pod, &result); err != nil {
		return result, err
	}
	logInfof("pod creation succeed,response is %+v", result)
	return result, nil
}

func cmdDel(args *skel.CmdArgs) error {
	n, err := loadNetconf(args.StdinData)
	if err != nil {
		return err
	}
	f, err := openLogFile(n.LogFile)
	defer f.Close()
	logger.SetOutput(f)
	if err != nil {
		logError(err)
		return err
	}
	argsMap, err := argsString2Map(args.Args)
	if err != nil {
		logError(err)
		return err
	}
	podNameSpace := argsMap["K8S_POD_NAMESPACE"]
	podName := argsMap["K8S_POD_NAME"]
	podIfName := args.IfName
	if podNameSpace == "" || podName == "" || podIfName == "" {
		return logErrorf("required CNI variable missing")
	}
	logInfof("receive pod deletion event : namespace %s, pod %s, ifname %s", podNameSpace, podName, podIfName)
	if err = deletePod(podNameSpace, podName, podIfName, args.Netns); err != nil {
		return logErrorf("failed to delete pod : %v", err)
	}
	return nil
}

func deletePod(namespace, name, ifname, netns string) error {
	client := rest.NewClient(rest.NewHttpClientUnix(constants.NodeAgentSock), "http://unix")
	url := fmt.Sprintf("%s%s/%s/%s/%s/%s", constants.Base, constants.Ports, namespace, name, ifname, netns)
	logInfof("send pod deletion request: pod namespace, pod name, pod ifname", namespace, name, ifname)
	code, err := client.Request("DELETE", url, nil, nil)
	if err != nil {
		return err
	}
	logInfof("send pod deletion succeed: pod namespace, pod name, code ", namespace, name, code)
	return err
}

func main() {
	cniFuncs := skel.CNIFuncs{Add: cmdAdd, Del: cmdDel}
	skel.PluginMainFuncs(cniFuncs, version.All, "demo-cni-plugin")
}
