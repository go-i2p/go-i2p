package router

import (
	"github.com/go-i2p/go-i2p/lib/i2pcontrol"
	"github.com/go-i2p/logger"
)

// startI2PControlServer initializes and starts the I2PControl RPC server if enabled.
// The server provides a JSON-RPC 2.0 interface for monitoring and managing the router.
//
// Returns:
//   - error: If server initialization or startup fails
func (r *Router) startI2PControlServer() error {
	if r.cfg.I2PControl == nil || !r.cfg.I2PControl.Enabled {
		log.WithFields(logger.Fields{
			"at":     "(Router) startI2PControlServer",
			"reason": "I2PControl disabled in configuration",
		}).Debug("I2PControl server not starting")
		return nil
	}

	log.WithFields(logger.Fields{
		"at":      "(Router) startI2PControlServer",
		"phase":   "startup",
		"address": r.cfg.I2PControl.Address,
		"https":   r.cfg.I2PControl.UseHTTPS,
	}).Info("starting I2PControl server")

	// Create statistics provider that wraps the router
	stats := i2pcontrol.NewRouterStatsProvider(r, "0.1.0-go")

	// Initialize I2PControl server
	server, err := i2pcontrol.NewServer(r.cfg.I2PControl, stats)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(Router) startI2PControlServer",
			"phase":  "startup",
			"reason": "failed to create I2PControl server",
		}).Error("I2PControl server initialization failed")
		return err
	}

	// Start the server
	if err := server.Start(); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(Router) startI2PControlServer",
			"phase":  "startup",
			"reason": "failed to start I2PControl server",
		}).Error("I2PControl server startup failed")
		return err
	}

	r.i2pcontrolServer = server

	log.WithFields(logger.Fields{
		"at":      "(Router) startI2PControlServer",
		"phase":   "startup",
		"address": r.cfg.I2PControl.Address,
	}).Info("I2PControl server started successfully")

	return nil
}

// stopI2PControlServer gracefully shuts down the I2PControl RPC server.
// This method is called during router shutdown to ensure clean termination.
func (r *Router) stopI2PControlServer() {
	if r.i2pcontrolServer == nil {
		log.WithFields(logger.Fields{
			"at":     "(Router) stopI2PControlServer",
			"reason": "I2PControl server not running",
		}).Debug("no I2PControl server to stop")
		return
	}

	log.WithFields(logger.Fields{
		"at":    "(Router) stopI2PControlServer",
		"phase": "shutdown",
	}).Info("stopping I2PControl server")

	r.i2pcontrolServer.Stop()

	log.WithFields(logger.Fields{
		"at":    "(Router) stopI2PControlServer",
		"phase": "shutdown",
	}).Info("I2PControl server stopped")
}
