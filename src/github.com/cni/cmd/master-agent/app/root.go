/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package app

import (
	"fmt"
	"github.com/cni/cmd/master-agent/app/options"
	"github.com/cni/pkg/util/flags"
	"github.com/cni/pkg/util/logs"
	"github.com/cni/pkg/util/server"
	"github.com/spf13/cobra"
	"k8s.io/klog"
	"math/rand"
	"os"
	"time"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "master-agent",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(app *cobra.Command, args []string) { },
}

func NewMasterCommand(srv *server.Server) *cobra.Command {
	masterFlags := options.NewMasterFlags()
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		flags.PrintFlags(cmd.Flags())
		Master := &options.MasterAgent{
			Server:           srv,
			MasterAgentFlags: *masterFlags,
		}
		if err := RUN(Master); err != nil {
			klog.Fatal(err)
		}
		return nil
	}
	masterFlags.AddFlags(rootCmd.Flags())
	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.master-agent.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rand.Seed(time.Now().UTC().UnixNano())
	if err := logs.InitLogs(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer logs.FlushLogs()
	NewMasterCommand(server.NewServerWithSignalHandler())
	flags.InitFlags()
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
