package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	nonInteractiveFlag = "not-interactive"
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "tlstool",
		Short: "TLSTool is a cli tool to easily generate X.509 certificates which can be used for TLS connections",
		Long:  "TLSTool is a cli tool to easily generate X.509 certificates which can be used for TLS connections without configuration files or having to setup a full PKI infrastructure",
	}

	pflags := rootCmd.PersistentFlags()
	pflags.Bool(nonInteractiveFlag, false, "Disable interactive mode")

	rootCmd.AddCommand(
		newGenCmd(),
		newVersionCmd(),
	)

	return rootCmd
}

func Execute() {
	rootCmd := newRootCmd()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
