/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package app

import (
	"fmt"
	"github.com/cni/cmd/node-agent/app/constants"
	"github.com/cni/cmd/node-agent/app/options"
	"github.com/cni/pkg/util/flags"
	"github.com/cni/pkg/util/server"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
	"net"
	"os"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "node-agent",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
}

func NewNodeAgentCmd(srv *server.Server) *cobra.Command {
	nodeFlags := options.NewNodeAgentFlags()
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		flags.PrintFlags(cmd.Flags())
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname :%s ", err)
		}
		hostIp := os.Getenv(constants.AgentNodeIP)
		if net.ParseIP(hostIp) == nil {
			return fmt.Errorf("node ip error format")
		}
		nodeAgent := &options.NodeAgent{
			Server:         srv,
			HostName:       hostname,
			HostIP:         hostIp,
			NodeAgentFlags: *nodeFlags,
		}
		if err := RUN(nodeAgent); err != nil {
			klog.Fatal(err)
		}
		return nil
	}
	nodeFlags.AddFlags(rootCmd.Flags())
	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.node-agent.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
