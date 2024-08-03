/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"fmt"
	"github.com/cni/cmd/master-agent/app"
	"github.com/cni/pkg/util/flags"
	"github.com/cni/pkg/util/logs"
	"github.com/cni/pkg/util/server"
	"math/rand"
	"os"
	"time"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	if err := logs.InitLogs(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer logs.FlushLogs()
	cmd := app.NewMasterCommand(server.NewServerWithSignalHandler())
	flags.InitFlags()
	//app.Execute()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
