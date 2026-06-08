package cli

import (
	"github.com/go-i2p/go-i2p/lib/cli/clicmd"
	"github.com/spf13/cobra"
)

// RegisterI2PControlCommand registers the i2pcontrol subcommand with the root command.
// This should be called during initialization after the main RootCmd is created.
func RegisterI2PControlCommand(rootCmd *cobra.Command) {
	rootCmd.AddCommand(clicmd.I2PControlCmd)
}
