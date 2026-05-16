// Package tuicmd provides the cobra subcommand for the go-i2p TUI.
package tuicmd

import (
	"net"

	tea "github.com/charmbracelet/bubbletea"
	tuipkg "github.com/go-i2p/go-i2p/lib/tui"
	"github.com/go-i2p/i2ptui"
	"github.com/go-i2p/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var log = logger.GetGoI2PLogger()

// New returns the cobra command that launches the bubbletea TUI.
func New() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Launch the I2P router TUI (terminal user interface)",
		Long: `Launch an interactive terminal UI for monitoring and managing the I2P router.
The TUI communicates via the I2PControl JSON-RPC interface. By default, all
connection parameters are derived from the config file.`,
		Run: run,
	}
}

func run(cmd *cobra.Command, args []string) {
	address := viper.GetString("i2pcontrol.address")
	password := viper.GetString("i2pcontrol.password")

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":      "tuiCmd",
			"address": address,
		}).Fatal("invalid i2pcontrol address format, expected host:port")
	}

	log.WithFields(logger.Fields{
		"at":       "tuiCmd",
		"host":     host,
		"port":     port,
		"password": password != "itoopie",
	}).Info("launching TUI")

	opts := []i2ptui.Option{
		i2ptui.WithHost(host),
		i2ptui.WithPort(port),
		i2ptui.WithPassword(password),
		i2ptui.WithPath("jsonrpc"),
	}

	m := tuipkg.New(password, address, opts...)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		log.WithError(err).Fatal("TUI exited with error")
	}
}
