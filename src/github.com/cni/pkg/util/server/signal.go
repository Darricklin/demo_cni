package server

import (
	"context"
	"k8s.io/klog"
	"os"
	"os/signal"
	"syscall"
)

var (
	onlyOneSignalHandler = make(chan struct{})
	shutdownSignals      = []os.Signal{syscall.SIGINT, syscall.SIGTERM}
)

func (s *Server) SetupSignalHandler() {
	close(onlyOneSignalHandler)
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		a := <-c
		klog.Errorf("receive signal : %v", a)
		cancel()
		b := <-c
		klog.Errorf("receive signal : %v", b)
		os.Exit(1) // second signal.Exit directly.
	}()
	s.Context = ctx
	s.Cancel = cancel
	reportCh := make(chan os.Signal)
	//signal.Notify(reportCh, syscall.SIGUSR2)
	signal.Notify(reportCh, syscall.SIGQUIT)
	go func() {
		for sig := range reportCh {
			klog.Errorf("receive signal %v", sig)
			s.Report()
		}
	}()

}
