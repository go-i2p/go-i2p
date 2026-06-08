package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-i2p/go-i2p/lib/cli"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/config/cliflags"
	"github.com/go-i2p/go-i2p/lib/config/configcmd"
	"github.com/go-i2p/go-i2p/lib/embedded"
	"github.com/go-i2p/go-i2p/lib/tui/tuicmd"
	"github.com/go-i2p/go-i2p/lib/util/signals"
	"github.com/go-i2p/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var log = logger.GetGoI2PLogger()

// RootCmd is the top-level cobra command for the go-i2p router.
var RootCmd = &cobra.Command{
	Use:   "go-i2p",
	Short: "I2P Router implementation in Go",
	Run: func(cmd *cobra.Command, args []string) {
		runRouter()
	},
}

func init() {
	cobra.OnInitialize(config.InitConfigOrExit)
	cliflags.RegisterAll(RootCmd)
	if err := cliflags.BindAll(RootCmd, viper.GetViper()); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":    "init",
			"phase": "startup",
		}).Fatal("failed to bind CLI flags to configuration")
	}
}

// runRouter is the thin main-entry-point that delegates the full router
// lifecycle to lib/embedded. It blocks until shutdown completes.
func runRouter() {
	// Wire SIGINT/SIGTERM to a cancellable context so that subsystems
	// awaiting ctx.Done() inside router.Run can react to shutdown signals
	// instead of blocking indefinitely on context.Background().
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go signals.Handle()

	routerCfg := config.GetRouterConfig()
	router, err := embedded.NewStandardEmbeddedRouter(routerCfg)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"phase":       "initialization",
			"reason":      "failed to create embedded router",
			"suggestion":  "check configuration values and system resources",
			"config_file": viper.ConfigFileUsed(),
		}).Errorf("failed to create i2p router: %s", err)
		os.Exit(1)
	}

	if err := router.Run(ctx); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"phase":      "runtime",
			"reason":     "router exited with error",
			"error_type": fmt.Sprintf("%T", err),
			"suggestion": "check logs for more details",
		}).Errorf("i2p router error: %s", err)
		os.Exit(1)
	}
}

func main() {
	RootCmd.AddCommand(configcmd.New())
	RootCmd.AddCommand(tuicmd.New())
	cli.RegisterI2PControlCommand(RootCmd)
	if err := RootCmd.Execute(); err != nil {
		log.Error(err)
		configcmd.DebugPrintConfig()
		os.Exit(1)
	}
}
