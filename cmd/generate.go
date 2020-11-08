package cmd

import (
	"github.com/spf13/cobra"
)

func newGenCmd() *cobra.Command {
	genCmd := &cobra.Command{
		Use: "gen",
		Aliases: []string{
			"generate",
		},
		Short: "Generate a certificate, private key, or certificate signing request",
	}

	genCmd.AddCommand(
		newGenCertCmd(),
		newGenKeyCmd(),
	)

	return genCmd
}
