/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"fmt"
	"github.com/cni/cmd/node-agent/app"
	"github.com/cni/pkg/util/flags"
	"github.com/cni/pkg/util/logs"
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
	flags.InitFlags()
	app.Execute()
}
