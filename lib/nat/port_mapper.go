package nat

import (
	"context"
	"sync"
	"time"

	nattraversal "github.com/go-i2p/go-nat-listener"
)

// PortMapperManager handles UPnP/NAT-PMP port mapping lifecycle:
// creation, retry with exponential backoff, lease renewal, and cleanup.
// Thread-safe: all methods are goroutine-safe.
type PortMapperManager struct {
	mu sync.Mutex

	// Configuration
	network      string        // "tcp" or "udp"
	internalPort int           // Local port to map
	leaseDur     time.Duration // Lease duration for port mapping (default: 1 hour)

	// Backoff configuration
	backoffCfg *BackoffConfig

	// State
	ctx     context.Context    // Parent context for lifecycle management
	cancel  context.CancelFunc // Cancel function for internal context
	wg      sync.WaitGroup     // WaitGroup for goroutine lifecycle
	mapper  nattraversal.PortMapper
	extPort int    // Currently mapped external port (0 if no mapping active)
	extIP   string // External IP address from mapper
	stopped bool   // Prevent duplicate Stop() calls
}

// PortMapperConfig configures a PortMapperManager.
type PortMapperConfig struct {
	// Network type ("tcp" or "udp")
	Network string

	// InternalPort is the local port to map
	InternalPort int

	// LeaseDuration is the lease duration for port mapping.
	// Default: 1 hour. Some NAT devices may enforce shorter leases.
	LeaseDuration time.Duration

	// InitialBackoff is the initial delay before the first retry attempt.
	// Default: 30 seconds.
	InitialBackoff time.Duration

	// MaxBackoff caps the exponential backoff between retries.
	// Default: 30 minutes.
	MaxBackoff time.Duration

	// BackoffFactor is the multiplier for exponential backoff.
	// Default: 2.0 (doubling).
	BackoffFactor float64

	// Context is the parent context for lifecycle management.
	// The manager stops when this context is cancelled.
	Context context.Context
}

// NewPortMapperManager creates a new port mapper lifecycle manager.
// Starts a background goroutine that retries port mapping on failure.
// Returns immediately; mapping happens asynchronously.
func NewPortMapperManager(cfg *PortMapperConfig) *PortMapperManager {
	// Apply defaults
	if cfg.LeaseDuration == 0 {
		cfg.LeaseDuration = 1 * time.Hour
	}
	if cfg.InitialBackoff == 0 {
		cfg.InitialBackoff = 30 * time.Second
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 30 * time.Minute
	}
	if cfg.BackoffFactor == 0 {
		cfg.BackoffFactor = 2.0
	}
	if cfg.Context == nil {
		cfg.Context = context.Background()
	}

	// Create internal context for lifecycle management
	ctx, cancel := context.WithCancel(cfg.Context)

	pmm := &PortMapperManager{
		network:      cfg.Network,
		internalPort: cfg.InternalPort,
		leaseDur:     cfg.LeaseDuration,
		backoffCfg: &BackoffConfig{
			Initial: cfg.InitialBackoff,
			Max:     cfg.MaxBackoff,
			Factor:  cfg.BackoffFactor,
		},
		ctx:    ctx,
		cancel: cancel,
	}

	// Start retry loop in background
	pmm.wg.Add(1)
	go pmm.retryLoop()

	return pmm
}

// retryLoop performs port mapping retry with exponential backoff.
// Exits when context is cancelled or mapping succeeds.
func (pmm *PortMapperManager) retryLoop() {
	defer pmm.wg.Done()

	backoff := pmm.backoffCfg.Initial

	for {
		// Wait for backoff delay or context cancellation
		if !WaitWithContext(pmm.ctx, backoff) {
			// Context cancelled, exit
			return
		}

		// Attempt port mapping
		if pmm.attemptMapping() {
			// Mapping succeeded, exit retry loop
			return
		}

		// Mapping failed, increase backoff
		backoff = pmm.backoffCfg.CalculateNextBackoff(backoff)
	}
}

// attemptMapping attempts to create a port mapper and map the port.
// Returns true if successful, false if should retry.
func (pmm *PortMapperManager) attemptMapping() bool {
	// Create port mapper
	mapper, err := pmm.createMapper()
	if err != nil {
		log.WithFields(map[string]interface{}{
			"network": pmm.network,
			"port":    pmm.internalPort,
			"error":   err,
		}).Debug("NAT port mapper unavailable; will retry")
		return false
	}

	gwIP, _ := mapper.GetExternalIP()
	log.WithFields(map[string]interface{}{
		"gateway": gwIP,
		"network": pmm.network,
		"port":    pmm.internalPort,
	}).Debug("NAT port mapping: attempting to map port")

	// Attempt to map the port
	externalPort, err := mapper.MapPort(pmm.network, pmm.internalPort, pmm.leaseDur)
	if err != nil {
		log.WithFields(map[string]interface{}{
			"gateway": gwIP,
			"network": pmm.network,
			"port":    pmm.internalPort,
			"error":   err,
		}).Debug("NAT port mapping failed; will retry")
		return false
	}

	// Success! Store the mapper and external port
	pmm.mu.Lock()
	pmm.mapper = mapper
	pmm.extPort = externalPort
	if extIP, err := mapper.GetExternalIP(); err == nil {
		pmm.extIP = extIP
	}
	pmm.mu.Unlock()

	log.WithFields(map[string]interface{}{
		"external_ip":   pmm.extIP,
		"external_port": externalPort,
		"internal_port": pmm.internalPort,
		"network":       pmm.network,
	}).Info("NAT port mapping succeeded")

	return true
}

// createMapper creates a port mapper with timeout context.
func (pmm *PortMapperManager) createMapper() (nattraversal.PortMapper, error) {
	mapCtx, mapCancel := context.WithTimeout(pmm.ctx, 5*time.Second)
	defer mapCancel()

	mapper, err := nattraversal.NewPortMapperContext(mapCtx)
	if err != nil {
		return nil, err
	}

	return mapper, nil
}

// GetExternalPort returns the currently mapped external port.
// Returns 0 if no mapping is active (mapping in progress or failed).
func (pmm *PortMapperManager) GetExternalPort() int {
	pmm.mu.Lock()
	defer pmm.mu.Unlock()
	return pmm.extPort
}

// GetExternalIP returns the external IP address from the port mapper.
// Returns empty string if no mapping is active.
func (pmm *PortMapperManager) GetExternalIP() string {
	pmm.mu.Lock()
	defer pmm.mu.Unlock()
	return pmm.extIP
}

// Stop stops the retry goroutine and unmaps the port.
// Blocks until cleanup completes or timeout (30s) elapses.
// RL-2 FIX: Increased timeout from 5s to 30s to allow time for ongoing UPnP/NAT-PMP operations
// to complete before goroutine exits. UPnP discovery and port mapping can take 10-20+ seconds
// on slow networks or unresponsive gateways.
func (pmm *PortMapperManager) Stop() error {
	pmm.mu.Lock()
	if pmm.stopped {
		pmm.mu.Unlock()
		return nil
	}
	pmm.stopped = true
	pmm.cancel() // Signal retry goroutine to exit
	pmm.mu.Unlock()

	// Wait for retry goroutine to exit (with timeout)
	// RL-2 FIX: Increased timeout from 5s to 30s to prevent goroutine leaks during SetIdentity
	done := make(chan struct{})
	go func() {
		pmm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Goroutine exited cleanly
	case <-time.After(30 * time.Second):
		log.Warn("Port mapper Stop() timed out waiting for retry goroutine (30s) - possible NAT operation hang")
	}

	// Unmap port if we have an active mapping
	pmm.mu.Lock()
	defer pmm.mu.Unlock()

	if pmm.mapper != nil && pmm.extPort > 0 {
		if err := pmm.mapper.UnmapPort(pmm.network, pmm.extPort); err != nil {
			log.WithFields(map[string]interface{}{
				"network":       pmm.network,
				"external_port": pmm.extPort,
				"error":         err,
			}).Warn("Failed to unmap port during Stop (non-fatal)")
			return err
		}
		log.WithFields(map[string]interface{}{
			"network":       pmm.network,
			"external_port": pmm.extPort,
		}).Debug("Port mapping cleaned up")
		pmm.mapper = nil
		pmm.extPort = 0
		pmm.extIP = ""
	}

	return nil
}
