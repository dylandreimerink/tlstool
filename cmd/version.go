package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	TlsToolVersion            = "unknown (not a released version)"
	TlsToolCommitHash         = "unknown (not a released version)"
	TlsToolGolangBuildVersion = "unknown (not a released version)"
)

func newVersionCmd() *cobra.Command {
	genCmd := &cobra.Command{
		Use:   "version",
		Short: "Prints version information",
		Run: func(cmd *cobra.Command, args []string) {
			b, err := cmd.Flags().GetBool("verbose")
			if err != nil {
				panic(err)
			}

			if !b {
				fmt.Println(TlsToolVersion)
				return
			}

			fmt.Printf(
				"TLSTool version: %s\nGIT Commit hash: %s\nGolang build version: %s\n",
				TlsToolVersion,
				TlsToolCommitHash,
				TlsToolGolangBuildVersion,
			)
		},
	}

	genCmd.Flags().BoolP("verbose", "v", false, "Print additional version information")

	return genCmd
}
