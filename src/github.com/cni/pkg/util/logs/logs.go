package logs

import (
	"flag"
	"k8s.io/klog"
)

//type KlogWriter struct {
//}
//
//func (writer KlogWriter) Write(data []byte) (n int, err error) {
//	klog.InfoDepth(1, string(data))
//	return len(data), nil
//}

func InitLogs() error {
	//klog.SetOutput(KlogWriter{})
	klog.InitFlags(nil)
	err := flag.Set("logtostderr", "false")
	return err
}

func FlushLogs() {
	klog.Flush()
}

//func NewLogger(prefix string) *log.Logger {
//	return log.New(KlogWriter{}, prefix, 0)
//}
