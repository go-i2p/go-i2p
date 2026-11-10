package embedded

import (
	"github.com/go-i2p/go-i2p/lib/router"
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

	// Re-arm the one-shot completion signal for this run. done was
	// previously shared for the lifetime of the Go struct, so a Stop() call
	// that happened before this successful Start() (e.g. defensive cleanup,
	// or an aborted startup rollback) would have already closed 'done',
	// causing Wait() to return immediately forever after even while the
	// router is actively running. Giving each Start()/Stop() pair its own
	// channel fixes this silent lifecycle bug.
	e.done = newRunCompletion()

	// Observe stops that originate inside the router rather than through this
	// façade. The I2PControl RPC Shutdown/Restart path calls Router.Stop()
	// directly, so without this the supervisor's done channel would never be
	// closed and Run()/Wait() would block forever after the router finished
	// shutting down — leaving remote shutdown dependent on SIGKILL.
	if stopped, ok := e.router.(stoppedNotifier); ok {
		if ch := stopped.Stopped(); ch != nil {
			go e.observeRouterStop(ch, e.done)
		}
	}

	// Capture publisher AFTER router starts (when it's initialized)
	// Publisher is initialized during router.Start() in launchPublisher()
	// We must capture it here, not during Configure()
	if r, ok := e.router.(*router.Router); ok {
		e.publisher = r.GetPublisher()
	}

	// Force immediate RouterInfo republish at startup
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
		// Even if not running, close the done channel to signal any Wait() goroutines.
		// This prevents indefinite blocking if Wait() is called before Start().
		doneCh := e.done
		e.mu.Unlock()

		// Close the done channel to wake up any Wait() callers
		if doneCh != nil {
			doneCh.close()
		}

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
	// The per-run once inside runCompletion prevents a double close if Stop(),
	// HardStop() and the router-stop watcher race.
	if doneCh != nil {
		doneCh.close()
	}

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Stop",
		"phase":  "shutdown",
		"reason": "router stopped successfully",
	}).Info("embedded router stopped")

	return nil
}

// Wait blocks until the router is stopped via Stop()/HardStop()/StopWithContext().
// Precondition: This method is safe to call at any time after the router is constructed.
// If called before Start(), it will block until either Start() is called and then Stop(),
// or Stop() is called directly. Callers that race Wait() against Start() will block
// until the first Stop() call completes.
func (e *StandardEmbeddedRouter) Wait() {
	e.mu.RLock()
	doneCh := e.done
	e.mu.RUnlock()

	if doneCh == nil {
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.Wait",
			"phase":  "waiting",
			"reason": "router not yet constructed",
		}).Debug("wait called on non-initialized router")
		return
	}

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Wait",
		"phase":  "running",
		"reason": "waiting for router shutdown",
	}).Debug("waiting for embedded router to stop")

	<-doneCh.ch

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.Wait",
		"phase":  "shutdown",
		"reason": "router wait completed",
	}).Debug("embedded router wait completed")
}

// stoppedNotifier is implemented by routers that report when a run finishes,
// regardless of who asked for the stop. *router.Router satisfies it; mocks and
// other Lifecycle implementations that do not are simply not observed.
type stoppedNotifier interface {
	Stopped() <-chan struct{}
}

// observeRouterStop completes the supervisor-side shutdown when the underlying
// router finishes a run on its own. It is woken either by the router signalling
// its stop or by the supervisor already having ended the run (Stop/HardStop
// closing done), so it never outlives the run it was started for.
func (e *StandardEmbeddedRouter) observeRouterStop(routerStopped <-chan struct{}, completion *runCompletion) {
	if completion == nil {
		return
	}
	select {
	case <-routerStopped:
	case <-completion.ch:
		// The supervisor already ended this run (Stop/HardStop); nothing to do.
		return
	}

	// Mirror what Stop() does for a supervisor-initiated shutdown: mark the run
	// finished so Close() is allowed, then wake Wait()/Run() callers.
	e.mu.Lock()
	e.running = false
	e.mu.Unlock()

	completion.close()

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.observeRouterStop",
		"phase":  "shutdown",
		"reason": "router reported its own stop (e.g. I2PControl RPC shutdown)",
	}).Info("embedded router observed router-initiated shutdown")
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
