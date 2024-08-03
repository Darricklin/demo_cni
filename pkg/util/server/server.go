package server

import (
	"context"
	"sync"
)

type Server struct {
	context.Context
	Cancel      context.CancelFunc
	StopWg      sync.WaitGroup
	ReportFuncs []func()
}

func NewServer() *Server {
	return &Server{
		StopWg: sync.WaitGroup{},
	}
}

func NewServerWithSignalHandler() *Server {
	srv := NewServer()
	srv.SetupSignalHandler()
	return srv
}
func (s *Server) AddReport(rf func()) {
	s.ReportFuncs = append(s.ReportFuncs, rf)
}
func (s *Server) Report() {
	for _, rf := range s.ReportFuncs {
		rf()
	}
}
