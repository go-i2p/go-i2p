package signals

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// defaultGracefulTimeout is the maximum time to wait for pre-shutdown handlers
// to complete before proceeding with interrupt handlers.
const defaultGracefulTimeout = 30 * time.Second

// minPerHandlerTimeout is the minimum timeout allocated to each individual
// pre-shutdown handler to prevent extremely short timeouts.
const minPerHandlerTimeout = 1 * time.Second

var (
	preShutdownMu       sync.RWMutex
	preShutdownHandlers []registeredHandler
	gracefulTimeout     = defaultGracefulTimeout
)

// RegisterPreShutdownHandler registers a handler that runs BEFORE the interrupt
// handlers during graceful shutdown. This is the appropriate place to register
// network announcement callbacks, such as sending a DatabaseStore message with
// zero addresses to inform peers that this router is going offline.
//
// Pre-shutdown handlers run in registration order (FIFO). Each handler is
// given an individual timeout (total timeout / handler count) so that a single
// stuck handler cannot block the entire shutdown chain.
//
// Per the I2P specification (common-structures RouterInfo notes), a router
// MUST send a DatabaseStore with zero addresses before disconnecting.
//
// Returns a HandlerID that can be passed to DeregisterPreShutdownHandler.
// Nil handlers are silently ignored and return -1.
func RegisterPreShutdownHandler(f Handler) HandlerID {
	if f == nil {
		return -1
	}
	preShutdownMu.Lock()
	defer preShutdownMu.Unlock()
	mu.Lock()
	id := nextID
	nextID++
	mu.Unlock()
	preShutdownHandlers = append(preShutdownHandlers, registeredHandler{id: id, fn: f})
	return id
}

// DeregisterPreShutdownHandler removes a previously registered pre-shutdown handler by ID.
func DeregisterPreShutdownHandler(id HandlerID) {
	preShutdownMu.Lock()
	defer preShutdownMu.Unlock()
	for i, h := range preShutdownHandlers {
		if h.id == id {
			preShutdownHandlers = append(preShutdownHandlers[:i], preShutdownHandlers[i+1:]...)
			return
		}
	}
}

// SetGracefulTimeout configures the maximum time to wait for pre-shutdown
// handlers to complete. If zero or negative, defaults to 30 seconds.
func SetGracefulTimeout(timeout time.Duration) {
	preShutdownMu.Lock()
	defer preShutdownMu.Unlock()
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
	preShutdownMu.RLock()
	snapshot := make([]registeredHandler, len(preShutdownHandlers))
	copy(snapshot, preShutdownHandlers)
	timeout := gracefulTimeout
	preShutdownMu.RUnlock()

	if len(snapshot) == 0 {
		return true
	}

	perHandler := timeout / time.Duration(len(snapshot))
	if perHandler < minPerHandlerTimeout {
		perHandler = minPerHandlerTimeout
	}

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
func runHandlerWithTimeout(h Handler, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "signals: panic in pre-shutdown handler: %v\n", r)
			}
		}()
		h()
	}()

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		fmt.Fprintf(os.Stderr, "signals: pre-shutdown handler timed out after %s\n", timeout)
		return false
	}
}
