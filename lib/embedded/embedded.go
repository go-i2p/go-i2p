package embedded

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/router"
	"github.com/go-i2p/logger"
)

var log = logger.GetGoI2PLogger()

// EmbeddedRouter defines the interface for an embeddable I2P router instance.
// This interface allows programmatic control of router lifecycle for applications
// that need to embed an I2P router rather than run it as a standalone process.
type EmbeddedRouter interface {
	// Configure initializes the router with the provided configuration.
	// Must be called before Start(). Returns error if configuration is invalid
	// or if router is already configured.
	Configure(cfg *config.RouterConfig) error

	// Start begins router operations, starting all subsystems (networking,
	// tunnels, netdb, etc.). Returns error if router fails to start or if
	// called before Configure().
	Start() error

	// Stop performs graceful shutdown of the router, allowing in-flight
	// operations to complete. Returns error if shutdown fails or times out.
	Stop() error

	// HardStop performs immediate termination of the router without waiting
	// for graceful cleanup. Use only when Stop() is insufficient.
	HardStop()

	// Wait blocks until the router has stopped.
	Wait()

	// Close releases all resources held by the router. The router must be
	// stopped before Close is called.
	Close() error

	// IsRunning reports whether the router is currently operational.
	IsRunning() bool

	// IsConfigured reports whether Configure has been called successfully.
	IsConfigured() bool
}

// StandardEmbeddedRouter is the standard implementation of EmbeddedRouter.
// It wraps a router.Router instance and manages its lifecycle with proper
// thread-safety and error handling.
type StandardEmbeddedRouter struct {
	// router is the underlying I2P router instance
	router *router.Router

	// cfg stores the router configuration
	cfg *config.RouterConfig

	// mu protects concurrent access to router state
	mu sync.RWMutex

	// configured tracks whether Configure() has been called successfully
	configured bool

	// running tracks whether the router is currently running
	running bool
}

// NewStandardEmbeddedRouter creates a new embedded router instance.
// The router is automatically configured with the provided config.
// Call Start() to begin router operations.
//
// Returns error if the configuration is nil or invalid, or if router creation fails.
func NewStandardEmbeddedRouter(cfg *config.RouterConfig) (*StandardEmbeddedRouter, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	log.WithFields(logger.Fields{
		"at":     "NewStandardEmbeddedRouter",
		"phase":  "initialization",
		"reason": "creating embedded router instance",
	}).Debug("creating new standard embedded router")

	e := &StandardEmbeddedRouter{
		cfg:        cfg,
		configured: false,
		running:    false,
	}

	// Auto-configure the router so callers don't need a separate Configure() call.
	// Configure() creates the underlying router instance using the provided config.
	if err := e.Configure(cfg); err != nil {
		return nil, fmt.Errorf("auto-configure failed: %w", err)
	}

	return e, nil
}

// Configure initializes the router with the provided configuration.
// This method creates the underlying router instance but does not start it.
//
// Note: NewStandardEmbeddedRouter already calls Configure() internally.
// Callers using the constructor do NOT need to call Configure() again.
// Calling Configure() on an already-configured router returns nil (no-op)
// to prevent errors from the documented constructor + Configure pattern.
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
		return fmt.Errorf("cannot reconfigure running router")
	}

	if cfg == nil {
		return fmt.Errorf("configuration cannot be nil")
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
		return fmt.Errorf("failed to create router: %w", err)
	}

	e.router = routerInstance
	e.cfg = cfg
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
func (e *StandardEmbeddedRouter) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.configured {
		return fmt.Errorf("router must be configured before starting")
	}

	if e.running {
		return fmt.Errorf("router is already running")
	}

	if e.router == nil {
		return fmt.Errorf("router instance is nil - configuration may have failed")
	}

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Start",
		"phase":  "startup",
		"reason": "starting router subsystems",
	}).Info("starting embedded router")

	// Start the router subsystems
	if err := e.router.Start(); err != nil {
		return fmt.Errorf("router startup failed: %w", err)
	}
	e.running = true

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Start",
		"phase":  "running",
		"reason": "router subsystems started successfully",
	}).Info("embedded router started successfully")

	return nil
}

// Stop performs graceful shutdown of the router.
// This method stops all router subsystems and waits for them to shut down cleanly.
func (e *StandardEmbeddedRouter) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.Stop",
			"phase":  "shutdown",
			"reason": "router is not running",
		}).Debug("stop called on non-running router")
		return nil
	}

	if e.router == nil {
		return fmt.Errorf("router instance is nil")
	}

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Stop",
		"phase":  "shutdown",
		"reason": "initiating graceful shutdown",
	}).Info("stopping embedded router")

	// Stop the router subsystems
	e.router.Stop()
	e.running = false

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Stop",
		"phase":  "shutdown",
		"reason": "router stopped successfully",
	}).Info("embedded router stopped")

	return nil
}

// HardStop performs immediate termination without graceful cleanup.
// Unlike Stop(), this does not wait for subsystems to shut down cleanly.
// It calls Stop() with a short timeout, then marks the router stopped.
// Use this only when Stop() fails or when immediate termination is required.
func (e *StandardEmbeddedRouter) HardStop() {
	e.mu.Lock()

	if !e.running {
		e.mu.Unlock()
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.HardStop",
			"phase":  "shutdown",
			"reason": "router is not running",
		}).Debug("hard stop called on non-running router")
		return
	}

	if e.router == nil {
		e.mu.Unlock()
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.HardStop",
			"phase":  "shutdown",
			"reason": "router instance is nil",
		}).Warn("hard stop called but router instance is nil")
		return
	}

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.HardStop",
		"phase":  "shutdown",
		"reason": "forcing immediate termination",
	}).Warn("performing hard stop of embedded router")

	// Mark as not running BEFORE releasing the mutex so concurrent
	// Stop()/IsRunning() calls see the correct state immediately.
	// This prevents the double-stop race where Stop() also tries
	// to stop the router while HardStop's goroutine is doing so.
	router := e.router
	e.running = false
	e.mu.Unlock()

	// Attempt graceful stop with a 5-second timeout (mutex NOT held)
	done := make(chan struct{})
	go func() {
		router.Stop()
		close(done)
	}()

	select {
	case <-done:
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.HardStop",
			"phase":  "shutdown",
			"reason": "graceful stop completed within timeout",
		}).Info("embedded router hard stopped (graceful)")
	case <-time.After(5 * time.Second):
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.HardStop",
			"phase":  "shutdown",
			"reason": "graceful stop timed out, forcing resource release",
		}).Error("embedded router hard stop: graceful shutdown timed out")
		// Force-close the router to release resources even though the
		// graceful Stop() goroutine is still running in the background.
		// Close() calls ensureStopped() internally and releases transports,
		// sessions, and routing components. After Close() completes, the
		// orphaned Stop() goroutine should unblock and exit because the
		// router's context and channels are torn down.
		if err := router.Close(); err != nil {
			log.WithFields(logger.Fields{
				"at":    "StandardEmbeddedRouter.HardStop",
				"phase": "shutdown",
				"error": err.Error(),
			}).Error("force close after timeout failed")
		}
		// Wait briefly for the orphaned Stop() goroutine to exit now that
		// Close() has torn down the router.
		select {
		case <-done:
			log.WithFields(logger.Fields{
				"at":     "StandardEmbeddedRouter.HardStop",
				"phase":  "shutdown",
				"reason": "orphaned Stop() goroutine exited after Close()",
			}).Debug("orphaned Stop goroutine completed")
		case <-time.After(2 * time.Second):
			log.WithFields(logger.Fields{
				"at":     "StandardEmbeddedRouter.HardStop",
				"phase":  "shutdown",
				"reason": "orphaned Stop() goroutine still running after Close()",
			}).Warn("orphaned Stop goroutine did not exit after Close; goroutine leak")
		}
	}
}

// Wait blocks until the router shuts down.
// This method can be called after Start() to keep the router running until Stop() is called.
func (e *StandardEmbeddedRouter) Wait() {
	e.mu.RLock()
	router := e.router
	running := e.running
	e.mu.RUnlock()

	if !running || router == nil {
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.Wait",
			"phase":  "waiting",
			"reason": "router is not running",
		}).Debug("wait called on non-running router")
		return
	}

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Wait",
		"phase":  "running",
		"reason": "waiting for router shutdown",
	}).Debug("waiting for embedded router to stop")

	router.Wait()

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Wait",
		"phase":  "shutdown",
		"reason": "router wait completed",
	}).Debug("embedded router wait completed")
}

// Close releases all resources associated with the router.
// This should be called after Stop() to ensure proper cleanup.
func (e *StandardEmbeddedRouter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return fmt.Errorf("cannot close running router - call Stop() first")
	}

	if e.router == nil {
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.Close",
			"phase":  "cleanup",
			"reason": "router instance is nil",
		}).Debug("close called but router is nil")
		return nil
	}

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Close",
		"phase":  "cleanup",
		"reason": "releasing router resources",
	}).Info("closing embedded router")

	err := e.router.Close()
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.Close",
			"phase":  "cleanup",
			"reason": "error during router close",
		}).Error("failed to close router cleanly")
		return fmt.Errorf("failed to close router: %w", err)
	}

	e.router = nil
	e.configured = false

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Close",
		"phase":  "cleanup",
		"reason": "router closed successfully",
	}).Info("embedded router closed")

	return nil
}

// IsRunning returns true if the router is currently running.
func (e *StandardEmbeddedRouter) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

// IsConfigured returns true if the router has been configured.
func (e *StandardEmbeddedRouter) IsConfigured() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.configured
}
