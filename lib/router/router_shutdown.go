package router

import (
	"context"
	"sync"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-i2p/lib/util/logutil"

	"github.com/go-i2p/logger"
)

// logSubsystemStop logs a subsystem shutdown event with standard fields.
// This reduces duplication across the various stopXxx methods.
func logSubsystemStop(method, subsystem string) {
	log.WithFields(logger.Fields{
		"at":     method,
		"phase":  "shutdown",
		"reason": subsystem + " stopped",
	}).Debug(subsystem + " stopped")
}

// logShutdownStep logs a shutdown step with standard fields.
func logShutdownStep(step int, reason, message string) {
	log.WithFields(logger.Fields{
		"at":     "(Router) Stop",
		"phase":  "shutdown",
		"step":   step,
		"reason": reason,
	}).Debug(message)
}

// stopAllSubsystems shuts down all router subsystems in the correct order.
func (r *Router) stopAllSubsystems() {
	r.stopTunnelManager()
	r.stopBandwidthTracker()
	r.stopCongestionMonitor()
	r.stopPublisher()
	r.stopExplorer()
	r.stopFloodfillServer()
	r.stopI2CPServer()
	r.stopI2PControlServer()
	r.stopParticipantManager()
	r.stopGarlicRouter()
	r.stopNetDB()
	r.sendCloseSignal()
}

// checkAlreadyStopped returns true if router is not running.
func (r *Router) checkAlreadyStopped() bool {
	if !r.running {
		r.runMux.Unlock()
		log.WithFields(logger.Fields{
			"at":     "(Router) Stop",
			"phase":  "shutdown",
			"reason": "router not running",
		}).Debug("router already stopped")
		return true
	}
	return false
}

// armStoppedChannel prepares a fresh stopped-notification channel for a run.
// Must be called with runMux held for writing (Router.Start does this).
func (r *Router) armStoppedChannel() {
	r.stoppedCh = make(chan struct{})
	r.stoppedOnce = sync.Once{}
}

// Stopped returns a channel that is closed once a stop has brought the router's
// subsystems down. Supervisors use it to detect stops that were initiated
// inside the router rather than through them — most importantly the I2PControl
// RPC shutdown path, which calls Router.Stop() directly and would otherwise
// leave the supervisor blocked in Wait() forever, requiring SIGKILL to
// terminate the process.
//
// The signal is emitted before Stop() joins the goroutines still tracked on the
// router WaitGroup, because those (transport session readers, tunnel-build
// retries) only drain once the transports are closed by Close(). A supervisor
// that wakes on this channel is therefore expected to proceed with its own
// Close() step rather than treating the run as fully quiesced.
//
// The channel is re-armed on every successful Start(), so callers must invoke
// Stopped() after Start() to observe the current run. It returns nil before
// the router has ever started.
func (r *Router) Stopped() <-chan struct{} {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.stoppedCh
}

// signalStopped closes the stopped channel created by armStoppedChannel,
// telling supervisors the router's subsystems are down. Safe to call
// concurrently and repeatedly: the sync.Once guarantees a single close per run,
// so a Stop racing HardStop (or a repeated stop request) cannot panic.
func (r *Router) signalStopped() {
	r.runMux.Lock()
	defer r.runMux.Unlock()
	r.stoppedOnce.Do(func() {
		if ch := r.stoppedCh; ch != nil {
			close(ch)
		}
	})
}

// cancelRouterContext cancels the router context to signal shutdown.
func (r *Router) cancelRouterContext() {
	if r.cancel != nil {
		r.cancel()
		logShutdownStep(2, "context canceled to signal subsystems", "router context cancelled")
	}
}

// Stop initiates router shutdown and waits for all goroutines to complete.
// This method blocks until the router is fully stopped.
// It is the primary entry point for graceful shutdown, typically called from
// a signal handler or the I2PControl shutdown command.
// See also [Router].
func (r *Router) Stop() {
	log.WithFields(logger.Fields{
		"at":     "(Router) Stop",
		"phase":  "shutdown",
		"step":   1,
		"reason": "shutdown requested",
	}).Info("stopping router")
	r.runMux.Lock()

	if r.checkAlreadyStopped() {
		return
	}

	r.running = false
	r.runMux.Unlock()

	r.cancelRouterContext()
	r.stopAllSubsystems()

	// Notify supervisors that the stop is underway and its subsystems are down,
	// BEFORE joining the remaining goroutines. Transport session readers and
	// tunnel-build retries are tracked on r.wg and only drain once the
	// transports are closed, which happens in Close(); a supervisor waiting on
	// this signal can therefore proceed to Close() and finish the shutdown
	// instead of hanging on the join below. The I2PControl RPC shutdown path
	// needs this because it calls Router.Stop() directly and never goes through
	// the embedded façade.
	r.signalStopped()

	logShutdownStep(3, "waiting for goroutines to complete", "waiting for router goroutines to finish")
	r.wg.Wait()
	log.WithFields(logger.Fields{
		"at":     "(Router) Stop",
		"phase":  "shutdown",
		"step":   4,
		"reason": "all subsystems stopped",
	}).Info("router stopped successfully")
}

// StopWithContext initiates router shutdown like Stop, but respects the
// provided context for cancellation. If the context is cancelled before
// all goroutines finish, the method returns the context error. This allows
// HardStop to bound the time spent waiting for graceful shutdown.
func (r *Router) StopWithContext(ctx context.Context) error {
	log.WithFields(logger.Fields{
		"at":     "(Router) Stop",
		"phase":  "shutdown",
		"step":   1,
		"reason": "shutdown requested (with context)",
	}).Info("stopping router")
	r.runMux.Lock()

	if r.checkAlreadyStopped() {
		return nil
	}

	r.running = false
	r.runMux.Unlock()

	r.cancelRouterContext()
	r.stopAllSubsystems()

	// Signal before the join for the same reason as Stop(): the supervisor can
	// only drain the remaining transport/tunnel goroutines by calling Close(),
	// which it can do once the router reports itself stopped. The bounded join
	// below is then just an optimisation for the case where they drain on their
	// own.
	r.signalStopped()

	logShutdownStep(3, "waiting for goroutines to complete", "waiting for router goroutines to finish")

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.WithFields(logger.Fields{
			"at":     "(Router) Stop",
			"phase":  "shutdown",
			"step":   4,
			"reason": "all subsystems stopped",
		}).Info("router stopped successfully")
		return nil
	case <-ctx.Done():
		logShutdownStep(4, "context cancelled", "router stop interrupted by context")
		return ctx.Err()
	}
}

// stopNetDB shuts down the network database if it exists and logs the result.
func (r *Router) stopNetDB() {
	r.runMux.Lock()
	nd := r.netdb
	r.runMux.Unlock()

	if nd != nil {
		nd.Stop()
		logSubsystemStop("(Router) stopNetDB", "netDB")
	}
}

// stopGarlicRouter shuts down the garlic router if it exists and logs the result.
// This cancels the background processPendingMessages goroutine to prevent goroutine leaks.
func (r *Router) stopGarlicRouter() {
	r.runMux.Lock()
	gr := r.garlicRouter
	r.runMux.Unlock()

	if gr != nil {
		gr.Stop()
		logSubsystemStop("(Router) stopGarlicRouter", "garlic router")
	}
}

// stopBandwidthTracker shuts down the bandwidth tracker if it is running and logs the result.
func (r *Router) stopBandwidthTracker() {
	if r.bandwidthTracker != nil {
		r.bandwidthTracker.Stop()
		log.WithFields(logger.Fields{"at": "stopBandwidthTracker"}).Debug("Bandwidth tracker stopped")
	}
}

// stopTunnelManager shuts down the tunnel manager if it exists.
// This stops the tunnel pools and cleans up tunnel-related resources.
func (r *Router) stopTunnelManager() {
	if r.tunnelManager != nil {
		r.tunnelManager.Stop()
		logSubsystemStop("(Router) stopTunnelManager", "tunnel manager")
	}
}

// stopParticipantManager shuts down the participant manager if it exists.
func (r *Router) stopParticipantManager() {
	if r.participantManager != nil {
		r.participantManager.Stop()
		log.WithFields(logger.Fields{"at": "stopParticipantManager"}).Debug("Participant manager stopped")
	}
}

func (r *Router) stopI2CPServer() {
	if r.i2cpServer != nil {
		if err := r.i2cpServer.Stop(); err != nil {
			log.WithError(err).Error("Failed to stop I2CP server")
		} else {
			log.WithFields(logger.Fields{"at": "stopI2CPServer"}).Debug("I2CP server stopped")
		}
	}
}

// sendCloseSignal sends the close signal to the router channel without blocking.
// It uses a non-blocking send to prevent deadlocks if the channel is full or already signaled.
func (r *Router) sendCloseSignal() {
	if r.closeChnl == nil {
		log.WithFields(logger.Fields{"at": "sendCloseSignal"}).Debug("close channel already finalized, skipping send")
		return
	}
	select {
	case r.closeChnl <- true:
		log.WithFields(logger.Fields{"at": "sendCloseSignal"}).Debug("Router stop signal sent")
	default:
		log.WithFields(logger.Fields{"at": "sendCloseSignal"}).Debug("Router stop signal already sent or channel full")
	}
}

// Close closes any internal state and finalizes router resources so that nothing can start up again.
// This method performs final cleanup after Stop() to ensure all resources are released and the router
// cannot be restarted. Call Stop() before Close() for graceful shutdown; Close() will call Stop()
// if the router is still running.
//
// Resources released by Close():
//   - Transport layer connections (via TransportMuxer.Close())
//   - Active NTCP2 sessions
//   - Message router references
//   - Garlic router references
//   - Tunnel manager references
//   - Close channel
func (r *Router) Close() error {
	log.WithFields(logger.Fields{
		"at":     "(Router) Close",
		"phase":  "finalization",
		"step":   1,
		"reason": "finalizing router resources",
	}).Info("closing router and releasing all resources")

	r.ensureStopped()
	closeErr := r.closeTransports()
	r.clearActiveSessions()
	r.clearRoutingComponents()
	r.finalizeCloseChannel()

	log.WithFields(logger.Fields{
		"at":     "(Router) Close",
		"phase":  "finalization",
		"step":   9,
		"reason": "router finalization complete",
	}).Info("router closed successfully - all resources released")

	return closeErr
}

// ensureStopped stops the router if it is still running.
func (r *Router) ensureStopped() {
	r.runMux.RLock()
	isRunning := r.running
	r.runMux.RUnlock()

	if isRunning {
		log.WithFields(logger.Fields{
			"at":     "(Router) Close",
			"phase":  "finalization",
			"step":   2,
			"reason": "router still running, calling Stop() first",
		}).Debug("stopping router before close")
		r.Stop()
	}
}

// closeTransports closes the transport muxer and all underlying connections.
// Returns the first error encountered during transport shutdown.
func (r *Router) closeTransports() error {
	muxer := r.transports.Load()
	if muxer == nil {
		return nil
	}

	log.WithFields(logger.Fields{
		"at":     "(Router) Close",
		"phase":  "finalization",
		"step":   3,
		"reason": "closing transport layer",
	}).Debug("closing TransportMuxer")

	var closeErr error
	if err := muxer.Close(); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(Router) Close",
			"phase":  "finalization",
			"reason": "transport close failed",
		}).Warn("error closing transport muxer")
		closeErr = err
	}
	r.transports.Store(nil)
	return closeErr
}

// clearActiveSessions closes and removes all active NTCP2 sessions from the router.
// The map is replaced with an empty map (not nil) so that async cleanup callbacks
// calling delete() on the map after shutdown do not panic.
func (r *Router) clearActiveSessions() {
	r.sessionMutex.Lock()
	sessions := r.activeSessions
	// Replace with empty map instead of nil to prevent panics from
	// async session cleanup callbacks that may call delete() after shutdown.
	r.activeSessions = make(map[common.Hash]transport.TransportSession)
	r.sessionMutex.Unlock()

	sessionCount := len(sessions)
	for hash, session := range sessions {
		if err := session.Close(); err != nil {
			log.WithFields(logger.Fields{
				"at":        "(Router) clearActiveSessions",
				"phase":     "finalization",
				"peer_hash": logutil.HashPrefix(hash),
				"error":     err.Error(),
			}).Warn("failed to close transport session during shutdown")
		}
	}

	if sessionCount > 0 {
		log.WithFields(logger.Fields{
			"at":            "(Router) Close",
			"phase":         "finalization",
			"step":          4,
			"reason":        "cleared active sessions",
			"session_count": sessionCount,
		}).Debug("active sessions cleared")
	}
}

// clearRoutingComponents releases all message routing, garlic routing,
// tunnel manager, keystore, and NetDB references.
// Acquires runMux to prevent concurrent reads of these fields during shutdown.
func (r *Router) clearRoutingComponents() {
	r.runMux.Lock()
	r.messageRouter = nil
	r.garlicRouter = nil
	r.tunnelManager = nil
	r.inboundHandler = nil
	r.publisher = nil
	r.explorer = nil
	r.floodfillServer = nil
	r.netdb = nil
	r.runMux.Unlock()
	log.WithFields(logger.Fields{
		"at":     "(Router) Close",
		"phase":  "finalization",
		"step":   5,
		"reason": "message routing components cleared",
	}).Debug("message router, garlic router, tunnel manager, publisher, and NetDB references cleared")

	r.keystoreMux.Lock()
	r.keystore = nil
	r.keystoreMux.Unlock()
	log.WithFields(logger.Fields{
		"at":     "(Router) Close",
		"phase":  "finalization",
		"step":   6,
		"reason": "keystore reference cleared",
	}).Debug("keystore reference cleared (keys preserved on disk)")
}

// finalizeCloseChannel closes the router's close channel to signal complete finalization.
func (r *Router) finalizeCloseChannel() {
	r.closeOnce.Do(func() {
		if r.closeChnl != nil {
			// Do NOT close the channel here — closing races with
			// sendCloseSignal() which may still be sending. Just
			// nil it out so future sends become no-ops.
			r.closeChnl = nil
			log.WithFields(logger.Fields{
				"at":     "(Router) Close",
				"phase":  "finalization",
				"step":   8,
				"reason": "close channel finalized (not closed to avoid race with sendCloseSignal)",
			}).Debug("close channel finalized (set to nil, not closed)")
		}
	})
}
