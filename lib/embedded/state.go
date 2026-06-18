package embedded

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Start starts the embedded router and all of its subsystems.
// The router must be configured before calling Start. Returns an error if the
// router is already running, not configured, or the underlying router fails to start.
func (e *StandardEmbeddedRouter) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.configured {
		return oops.Errorf("router must be configured before starting")
	}

	if e.running {
		return oops.Errorf("router is already running")
	}

	if e.router == nil {
		return oops.Errorf("router instance is nil - configuration may have failed")
	}

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Start",
		"phase":  "startup",
		"reason": "starting router subsystems",
	}).Info("starting embedded router")

	// Start the router subsystems
	if err := e.router.Start(); err != nil {
		return oops.Wrapf(err, "router startup failed")
	}
	e.running = true
	e.done = make(chan struct{})

	// CRITICAL-6 FIX: Force immediate RouterInfo republish at startup
	// This flushes peer caches of old cached RouterInfo with different keys.
	// Normally DHT updates are slow (cache expiry), but this ensures immediate
	// propagation so peers start using new X25519 encryption key immediately.
	// This is critical for garlic message decryption to succeed quickly after startup.
	if e.publisher != nil {
		if err := e.publisher.ForceRouterInfoRepublish(); err != nil {
			log.WithFields(logger.Fields{
				"at":     "StandardEmbeddedRouter.Start",
				"reason": "force republish failed",
				"error":  err,
			}).Warn("failed to force RouterInfo republish at startup (non-fatal)")
		} else {
			log.WithFields(logger.Fields{
				"at":     "StandardEmbeddedRouter.Start",
				"reason": "RouterInfo republished immediately to floodfills",
			}).Info("forced immediate RouterInfo republish at startup")
		}
	}

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Start",
		"phase":  "running",
		"reason": "router subsystems started successfully",
	}).Info("embedded router started successfully")

	return nil
}

// Stop performs graceful shutdown of the router.
// This method stops all router subsystems and waits for them to shut down cleanly.
// The mutex is released before calling router.Stop() to prevent deadlock with
// goroutines that call IsRunning() during shutdown.

func (e *StandardEmbeddedRouter) Stop() error {
	e.mu.Lock()

	if !e.running {
		e.mu.Unlock()
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.Stop",
			"phase":  "shutdown",
			"reason": "router is not running",
		}).Debug("stop called on non-running router")
		return nil
	}

	if e.router == nil {
		e.mu.Unlock()
		return oops.Errorf("router instance is nil")
	}

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Stop",
		"phase":  "shutdown",
		"reason": "initiating graceful shutdown",
	}).Info("stopping embedded router")

	// Capture the router and mark as not running before releasing the lock.
	// This prevents new operations from starting while we shut down, and
	// prevents deadlock with goroutines calling IsRunning() during router.Stop().
	r := e.router
	e.running = false
	doneCh := e.done
	e.mu.Unlock()

	// Stop the router subsystems (potentially blocking) without holding the lock
	r.Stop()

	// H7 FIX: Signal Wait() callers that the router has stopped.
	// Use sync.Once to prevent panic if Stop() and HardStop() race.
	e.doneOnce.Do(func() {
		if doneCh != nil {
			close(doneCh)
		}
	})

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Stop",
		"phase":  "shutdown",
		"reason": "router stopped successfully",
	}).Info("embedded router stopped")

	return nil
}

// Wait blocks until the router is stopped via Stop()/HardStop()/StopWithContext().
//
// Precondition: Wait must be called *after* Start() has returned successfully.
// If Wait is called before Start() — or after Stop() has already completed —
// it returns immediately because there is no live shutdown channel to await.
// Callers that race Wait against Start (e.g. spawning `go r.Wait()` in one
// goroutine while another goroutine calls Start) must synchronize themselves;
// this method does not block until Start populates the internal done channel.
// See AUDIT.md M-5.
func (e *StandardEmbeddedRouter) Wait() {
	e.mu.RLock()
	running := e.running
	doneCh := e.done
	e.mu.RUnlock()

	if !running || doneCh == nil {
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

	<-doneCh

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Wait",
		"phase":  "shutdown",
		"reason": "router wait completed",
	}).Debug("embedded router wait completed")
}

// IsRunning returns true if the router has been started and has not yet been stopped.
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
