package cmd

import (
	"fmt"

	app_identity "github.com/H-BF/corlib/app/identity"
	"github.com/spf13/cobra"
)

const (
	appName      = "visor-cli"
	shortAppDesc = "command-line network traffic analyzer."
	longAppDesc  = `visor is a CLI for analyzing traces of the network traffic coming through nftables rules marked as 'nftrace set 1'`
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Version: fmt.Sprintf("v%s", app_identity.Version),
		Use:     appName,
		Short:   shortAppDesc,
		Long:    longAppDesc,
	}
	rootCmd.AddCommand(newWatcherCommand())
	return rootCmd
}

// Execute root command.
func Execute() {
	_ = newRootCmd().Execute()
}
