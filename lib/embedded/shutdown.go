package embedded

import (
	"context"
	"time"

	"github.com/go-i2p/go-i2p/lib/router"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// HardStop performs immediate termination without graceful cleanup.
// Unlike Stop, this does not wait for subsystems to shut down cleanly.
// It calls StopWithContext with a 5-second deadline, then marks the router stopped.
// Use this only when Stop fails or when immediate termination is required.
func (e *StandardEmbeddedRouter) HardStop() {
	router := e.prepareHardStop()
	if router == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := router.StopWithContext(ctx); err != nil {
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.HardStop",
			"phase":  "shutdown",
			"reason": "graceful stop timed out, forcing resource release",
			"error":  err.Error(),
		}).Error("embedded router hard stop: graceful shutdown timed out")
		e.forceCloseRouter(router)
	} else {
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.HardStop",
			"phase":  "shutdown",
			"reason": "graceful stop completed within timeout",
		}).Info("embedded router hard stopped (graceful)")
	}
}

// prepareHardStop validates the router state and marks it as not running
// under the mutex. Returns the router instance, or nil if stop is not needed.

func (e *StandardEmbeddedRouter) prepareHardStop() router.Lifecycle {
	e.mu.Lock()

	if !e.running {
		e.mu.Unlock()
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.HardStop",
			"phase":  "shutdown",
			"reason": "router is not running",
		}).Debug("hard stop called on non-running router")
		return nil
	}

	if e.router == nil {
		e.mu.Unlock()
		log.WithFields(logger.Fields{
			"at":     "StandardEmbeddedRouter.HardStop",
			"phase":  "shutdown",
			"reason": "router instance is nil",
		}).Warn("hard stop called but router instance is nil")
		return nil
	}

	log.WithFields(logger.Fields{
		"at":     "StandardEmbeddedRouter.HardStop",
		"phase":  "shutdown",
		"reason": "forcing immediate termination",
	}).Warn("performing hard stop of embedded router")

	r := e.router
	e.running = false
	doneCh := e.done
	e.mu.Unlock()

	// H7 FIX: Signal Wait() callers that the router is stopping.
	// Use sync.Once to prevent panic if Stop() and HardStop() race.
	e.doneOnce.Do(func() {
		if doneCh != nil {
			close(doneCh)
		}
	})

	return r
}

// forceCloseRouter calls Close() on the router to release resources after
// a timed-out StopWithContext call.

func (e *StandardEmbeddedRouter) forceCloseRouter(r router.Lifecycle) {
	if err := r.Close(); err != nil {
		log.WithFields(logger.Fields{
			"at":    "StandardEmbeddedRouter.HardStop",
			"phase": "shutdown",
			"error": err.Error(),
		}).Error("force close after timeout failed")
	}
}

// Close releases all resources associated with the router.
// This should be called after Stop to ensure proper cleanup. Returns an error
// if the router is still running.
func (e *StandardEmbeddedRouter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return oops.Errorf("cannot close running router - call Stop() first")
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
		return oops.Wrapf(err, "failed to close router")
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
