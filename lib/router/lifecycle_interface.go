package router

import (
	"context"
)

// Lifecycle defines the minimal interface for a router instance needed by
// the embedded façade. This allows StandardEmbeddedRouter to depend on an
// interface rather than a concrete *Router type, enabling testability and
// alternative implementations.
//
// Lifecycle encompasses the router's lifecycle management methods: startup,
// graceful shutdown, hard shutdown with timeout, waiting for completion, and
// resource cleanup.
type Lifecycle interface {
	// Start begins router operations, starting all subsystems (networking,
	// tunnels, netdb, etc.). Returns error if router fails to start or if
	// called on an already-running router.
	Start() error

	// Stop performs graceful shutdown of the router, allowing in-flight
	// operations to complete. Does not return an error.
	Stop()

	// StopWithContext performs graceful shutdown like Stop, but respects the
	// provided context for cancellation. If the context is cancelled before
	// all goroutines finish, returns the context error.
	// This allows hard stop to bound the time spent waiting for graceful shutdown.
	StopWithContext(ctx context.Context) error

	// Wait blocks until the router has stopped.
	Wait()

	// Close releases all resources held by the router. The router must be
	// stopped before Close is called.
	Close() error
}
