package embedded

import (
	"fmt"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/router"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Configure applies the given configuration to the router.
// It is a no-op if the router is already configured. Returns an error if
// the router is currently running or if cfg is nil.
func (e *StandardEmbeddedRouter) Configure(cfg *config.RouterConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.configured {
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.Configure",
			"phase":  "configuration",
			"reason": "router is already configured",
		}).Debug("Configure called on already-configured router (no-op)")
		return nil
	}

	if e.running {
		return oops.Errorf("cannot reconfigure running router")
	}

	if cfg == nil {
		return oops.Errorf("configuration cannot be nil")
	}

	log.WithFields(logger.Fields{
		"at":          "StandardEmbeddedRouter.Configure",
		"phase":       "configuration",
		"reason":      "initializing router with configuration",
		"base_dir":    cfg.BaseDir,
		"working_dir": cfg.WorkingDir,
	}).Info("configuring embedded router")

	// Create the router instance with the provided configuration
	routerInstance, err := router.CreateRouter(cfg)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":         "StandardEmbeddedRouter.Configure",
			"phase":      "configuration",
			"reason":     "router creation failed",
			"error_type": fmt.Sprintf("%T", err),
		}).Error("failed to create router instance")
		return oops.Wrapf(err, "failed to create router")
	}

	e.router = routerInstance
	e.cfg = cfg
	// CRITICAL-6 FIX: Capture publisher reference for startup republish
	// routerInstance is *router.Router, so we can access publisher directly
	e.publisher = routerInstance.GetPublisher()
	e.configured = true

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Configure",
		"phase":  "configuration",
		"reason": "router instance created successfully",
	}).Info("embedded router configured successfully")

	return nil
}

// Start begins router operations. The router must be configured before calling Start().
// This method starts all router subsystems and blocks until the router is fully started.
