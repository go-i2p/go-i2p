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

var (
	preShutdownMu       sync.RWMutex
	preShutdownHandlers []Handler
	gracefulTimeout     = defaultGracefulTimeout
)

// RegisterPreShutdownHandler registers a handler that runs BEFORE the interrupt
// handlers during graceful shutdown. This is the appropriate place to register
// network announcement callbacks, such as sending a DatabaseStore message with
// zero addresses to inform peers that this router is going offline.
//
// Pre-shutdown handlers run in registration order (FIFO) and each handler is
// protected against panics. All pre-shutdown handlers must complete (or the
// graceful timeout must expire) before interrupt handlers are invoked.
//
// Per the I2P specification (common-structures RouterInfo notes), a router
// MUST send a DatabaseStore with zero addresses before disconnecting.
//
// Nil handlers are silently ignored.
func RegisterPreShutdownHandler(f Handler) {
	if f == nil {
		return
	}
	preShutdownMu.Lock()
	defer preShutdownMu.Unlock()
	preShutdownHandlers = append(preShutdownHandlers, f)
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

// handlePreShutdown runs all registered pre-shutdown handlers with a timeout.
// Returns true if all handlers completed within the timeout, false otherwise.
func handlePreShutdown() bool {
	preShutdownMu.RLock()
	snapshot := make([]Handler, len(preShutdownHandlers))
	copy(snapshot, preShutdownHandlers)
	timeout := gracefulTimeout
	preShutdownMu.RUnlock()

	if len(snapshot) == 0 {
		return true
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, h := range snapshot {
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "signals: panic in pre-shutdown handler: %v\n", r)
					}
				}()
				h()
			}()
		}
	}()

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		fmt.Fprintf(os.Stderr, "signals: pre-shutdown handlers timed out after %s\n", timeout)
		return false
	}
}
