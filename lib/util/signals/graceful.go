package signals

import (
	"fmt"
	"os"
	"time"
)

// defaultGracefulTimeout is the maximum time to wait for pre-shutdown handlers
// to complete before proceeding with interrupt handlers.
const defaultGracefulTimeout = 30 * time.Second

// minPerHandlerTimeout is the minimum timeout allocated to each individual
// pre-shutdown handler to prevent extremely short timeouts.
const minPerHandlerTimeout = 1 * time.Second

var gracefulTimeout time.Duration

// init sets the default graceful timeout
func init() {
	gracefulTimeout = defaultGracefulTimeout
}

// RegisterPreShutdownHandler registers a handler that runs BEFORE the interrupt
// handlers during graceful shutdown. This is the appropriate place to register
// network announcement callbacks, such as sending a DatabaseStore message with
// zero addresses to inform peers that this router is going offline.
//
// Pre-shutdown handlers run in registration order (FIFO). Each handler is
// given an individual timeout (total timeout / handler count) so that a single
// stuck handler cannot block the entire shutdown chain.
//
// Per convention (not formally specified in common-structures.rst), a router
// MAY send a DatabaseStore with zero addresses before disconnecting.
//
// Returns a HandlerID that can be passed to DeregisterPreShutdownHandler.
// Nil handlers are silently ignored and return -1.
// M-27 Consolidation: Uses shared registerHandler pattern from signals.go.
func RegisterPreShutdownHandler(f Handler) HandlerID {
	id := registerHandler(f, &preShutdownHandlers)
	if id >= 0 {
		log.WithField("handler_id", id).Debug("registered pre-shutdown handler")
	}
	return id
}

// DeregisterPreShutdownHandler removes a previously registered pre-shutdown handler by ID.
func DeregisterPreShutdownHandler(id HandlerID) {
	deregisterHandler(id, &preShutdownHandlers)
}

// SetGracefulTimeout configures the maximum time to wait for pre-shutdown
// handlers to complete. If zero or negative, defaults to 30 seconds.
func SetGracefulTimeout(timeout time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	if timeout <= 0 {
		gracefulTimeout = defaultGracefulTimeout
	} else {
		gracefulTimeout = timeout
	}
}

// handlePreShutdown runs all registered pre-shutdown handlers with individual
// timeouts. Each handler gets an equal share of the total graceful timeout,
// with a minimum of 1 second per handler. If a handler exceeds its timeout,
// execution moves to the next handler instead of blocking the entire chain.
// Returns true if all handlers completed within their timeouts, false otherwise.
func handlePreShutdown() bool {
	mu.RLock()
	snapshot := make([]registeredHandler, len(preShutdownHandlers))
	copy(snapshot, preShutdownHandlers)
	timeout := gracefulTimeout
	mu.RUnlock()

	if len(snapshot) == 0 {
		return true
	}

	perHandler := max(timeout/time.Duration(len(snapshot)), minPerHandlerTimeout)

	allCompleted := true
	for _, h := range snapshot {
		if !runHandlerWithTimeout(h.fn, perHandler) {
			allCompleted = false
		}
	}
	return allCompleted
}

// runHandlerWithTimeout executes a single handler in a goroutine with the
// given timeout. Returns true if the handler completed, false if it timed out.
//
// Note: Go cannot pre-empt arbitrary user code, so a handler that does not
// return on its own continues running in the background goroutine after this
// function returns false; the caller is released but the goroutine survives
// until h() finally returns. The done channel is buffered (cap 1) so the
// goroutine never blocks when it does eventually finish, but a handler that
// loops forever leaks one goroutine for the lifetime of the process. Handlers
// SHOULD honour timeouts internally (e.g., via a context); the per-handler
// timeout enforced here is a defensive ceiling on the shutdown sequence, not
// a hard kill.
func runHandlerWithTimeout(h Handler, timeout time.Duration) bool {
	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "signals: panic in pre-shutdown handler: %v\n", r)
				done <- false
			}
		}()
		h()
		done <- true
	}()

	select {
	case completed := <-done:
		return completed
	case <-time.After(timeout):
		log.WithField("timeout", timeout).Warn("pre-shutdown handler timed out")
		fmt.Fprintf(os.Stderr, "signals: pre-shutdown handler timed out after %s\n", timeout)
		return false
	}
}
