package embedded

import (
	"context"
	"sync"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/router"
)

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

	// Run executes the full router lifecycle from configuration to shutdown.
	// It handles signal registration, network preflight checks, router creation,
	// startup, and graceful shutdown. This is the recommended entry point for
	// embedding the router in other applications.
	Run(ctx context.Context) error
}

// StandardEmbeddedRouter is the standard implementation of EmbeddedRouter.
// It wraps a router.Lifecycle instance and manages its lifecycle with proper
// thread-safety and error handling.
type StandardEmbeddedRouter struct {
	// router is the underlying I2P router instance (interface for testability)
	router router.Lifecycle

	// cfg stores the router configuration
	cfg *config.RouterConfig

	// publisher reference to force RouterInfo republish at startup
	// This ensures peer caches are flushed of old RouterInfo when router restarts
	publisher *netdb.Publisher

	// mu protects concurrent access to router state
	mu sync.RWMutex

	// configured tracks whether Configure() has been called successfully
	configured bool

	// running tracks whether the router is currently running
	running bool

	// done is the completion signal for the current run. Wait() selects on the
	// channel inside it instead of capturing and using the router pointer,
	// avoiding TOCTOU races where Stop()+Close() could nil the pointer between
	// RUnlock and router.Wait().
	//
	// The channel and the sync.Once that guards its close live in one
	// per-run object (see runCompletion) so that a watcher left over from an
	// earlier run can never mark a later run complete. Start() re-arms it for
	// every run; it is never nil after construction.
	done *runCompletion
}

// runCompletion is the one-shot completion signal for a single Start()/Stop()
// pair. Bundling the channel with its own sync.Once keeps the "closed exactly
// once" guarantee scoped to the run it belongs to, which matters because
// Stop(), HardStop() and the router-initiated stop watcher can all race.
type runCompletion struct {
	ch   chan struct{}
	once sync.Once
}

// newRunCompletion builds the completion signal for a fresh run.
func newRunCompletion() *runCompletion {
	return &runCompletion{ch: make(chan struct{})}
}

// close marks the run complete, exactly once.
func (rc *runCompletion) close() {
	rc.once.Do(func() { close(rc.ch) })
}

// NewStandardEmbeddedRouter creates a new embedded router instance.
// The router is automatically configured with the provided config.
// Call Start() to begin router operations.
// Returns error if the configuration is nil or invalid, or if router creation fails.
