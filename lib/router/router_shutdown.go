package router

import (
	"context"

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

// cancelRouterContext cancels the router context to signal shutdown.
func (r *Router) cancelRouterContext() {
	if r.cancel != nil {
		r.cancel()
		logShutdownStep(2, "context canceled to signal subsystems", "router context cancelled")
	}
}

// Stop initiates router shutdown and waits for all goroutines to complete.
// This method blocks until the router is fully stopped.
func (r *Router) Stop() {
	logShutdownStep(1, "shutdown requested", "stopping router")
	r.runMux.Lock()

	if r.checkAlreadyStopped() {
		return
	}

	r.running = false
	r.runMux.Unlock()

	r.cancelRouterContext()
	r.stopAllSubsystems()

	logShutdownStep(3, "waiting for goroutines to complete", "waiting for router goroutines to finish")
	r.wg.Wait()
	logShutdownStep(4, "all subsystems stopped", "router stopped successfully")
}

// StopWithContext initiates router shutdown like Stop, but respects the
// provided context for cancellation. If the context is cancelled before
// all goroutines finish, the method returns the context error. This allows
// HardStop to bound the time spent waiting for graceful shutdown.
func (r *Router) StopWithContext(ctx context.Context) error {
	logShutdownStep(1, "shutdown requested (with context)", "stopping router")
	r.runMux.Lock()

	if r.checkAlreadyStopped() {
		return nil
	}

	r.running = false
	r.runMux.Unlock()

	r.cancelRouterContext()
	r.stopAllSubsystems()

	logShutdownStep(3, "waiting for goroutines to complete", "waiting for router goroutines to finish")

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logShutdownStep(4, "all subsystems stopped", "router stopped successfully")
		return nil
	case <-ctx.Done():
		logShutdownStep(4, "context cancelled", "router stop interrupted by context")
		return ctx.Err()
	}
}

// stopNetDB shuts down the network database if it exists and logs the result.
func (r *Router) stopNetDB() {
	if r.netdb != nil {
		r.netdb.Stop()
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
	if r.transports == nil {
		return nil
	}

	log.WithFields(logger.Fields{
		"at":     "(Router) Close",
		"phase":  "finalization",
		"step":   3,
		"reason": "closing transport layer",
	}).Debug("closing TransportMuxer")

	var closeErr error
	if err := r.transports.Close(); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(Router) Close",
			"phase":  "finalization",
			"reason": "transport close failed",
		}).Warn("error closing transport muxer")
		closeErr = err
	}
	r.transports = nil
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
			close(r.closeChnl)
			r.closeChnl = nil
			log.WithFields(logger.Fields{
				"at":     "(Router) Close",
				"phase":  "finalization",
				"step":   8,
				"reason": "close channel finalized",
			}).Debug("close channel closed")
		}
	})
}
