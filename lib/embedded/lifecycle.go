package embedded

import (
	"context"

	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/util/closeables"
	"github.com/go-i2p/go-i2p/lib/util/signals"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"github.com/spf13/viper"
)

// Run executes the full router lifecycle from configuration to shutdown.
// It handles signal registration, network preflight checks, router creation,
// startup, and graceful shutdown.
//
// Run is the recommended entry point for embedding the router in other applications.
// It abstracts the entire lifecycle management that was previously scattered
// across main.go functions.
//
// The context allows callers to participate in cancellation, though the router
// will continue running until it receives a SIGINT/SIGTERM signal or Stop() is called.
func (e *StandardEmbeddedRouter) Run(ctx context.Context) error {
	// Register signal handlers for the lifecycle
	reloadID := signals.RegisterReloadHandler(func() {
		e.handleReloadSignal()
	})
	defer signals.DeregisterReloadHandler(reloadID)

	interruptID := signals.RegisterInterruptHandler(func() {
		e.handleInterruptSignal()
	})
	defer signals.DeregisterInterruptHandler(interruptID)

	// Log startup configuration
	if viper.ConfigFileUsed() == "" {
		log.WithFields(logger.Fields{
			"phase":    "startup",
			"reason":   "no config file found, using defaults",
			"strategy": "defaults_and_flags",
		}).Warn("no configuration file loaded, using default values and command-line flags")
	} else {
		log.WithFields(logger.Fields{
			"phase":       "startup",
			"reason":      "configuration file loaded",
			"config_file": viper.ConfigFileUsed(),
		}).Info("loaded configuration from file")
	}

	// Log NetDB path
	routerCfg := config.GetRouterConfig()
	if routerCfg != nil && routerCfg.NetDB != nil {
		log.WithFields(logger.Fields{
			"netdb_path": routerCfg.NetDB.Path,
			"source":     "configuration",
		}).Info("using netDb path: " + routerCfg.NetDB.Path)
	}

	// Run network pre-checks (non-blocking failure)
	if err := bootstrap.TestNetworkConnectivity(); err != nil {
		log.WithFields(logger.Fields{
			"error":  err.Error(),
			"reason": "network connectivity check failed",
		}).Warn("Network connectivity test failed - router may not be able to connect to peers")
	}

	// Start the router
	log.WithFields(logger.Fields{
		"phase":  "startup",
		"reason": "starting router subsystems",
	}).Info("starting embedded router")

	if err := e.Start(); err != nil {
		return oops.Wrapf(err, "failed to start router")
	}

	// Bridge context cancellation into the shutdown path so callers that
	// pass a cancellable context (e.g. signal.NotifyContext) can drive
	// shutdown without relying on the package-level signal handler.
	ctxDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			log.WithFields(logger.Fields{
				"phase":  "shutdown",
				"reason": "context cancelled",
			}).Info("context cancelled, initiating router shutdown")
			e.handleInterruptSignal()
		case <-ctxDone:
		}
	}()

	// Wait for the router to stop (blocks until signal or Stop() is called)
	e.Wait()
	close(ctxDone)

	// Perform final cleanup
	log.WithFields(logger.Fields{
		"phase":  "shutdown",
		"reason": "router shutdown complete, cleaning up",
	}).Info("closing embedded router")

	// Always close all registered resources, even if e.Close() fails
	defer closeables.CloseAll()

	if err := e.Close(); err != nil {
		return oops.Wrapf(err, "failed to close router")
	}

	return nil
}

// handleReloadSignal handles SIGHUP by reloading configuration and applying it to the router.
func (e *StandardEmbeddedRouter) handleReloadSignal() {
	if err := viper.ReadInConfig(); err != nil {
		log.Errorf("failed to reload config: %s", err)
		return
	}

	newCfg, err := config.NewRouterConfigFromViper()
	if err != nil {
		log.WithError(err).Error("invalid configuration after reload: cannot apply configuration")
		return
	}
	config.SetRouterConfig(newCfg)

	log.WithFields(logger.Fields{
		"phase":  "reload",
		"reason": "SIGHUP signal received",
	}).Info("configuration reloaded from signal")
}

// handleInterruptSignal handles SIGINT/SIGTERM by stopping the router.
func (e *StandardEmbeddedRouter) handleInterruptSignal() {
	log.WithFields(logger.Fields{
		"phase":  "shutdown",
		"reason": "interrupt signal received",
	}).Info("stopping embedded router")

	if err := e.Stop(); err != nil {
		log.WithError(err).Error("error during graceful stop, forcing hard stop")
		e.HardStop()
	}
}
