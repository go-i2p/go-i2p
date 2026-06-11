package netdb

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
)

// admissionConfig holds the configuration constants for an admission controller.
type admissionConfig struct {
	window      time.Duration
	perSource   int
	trackedMax  int
	pressurePct int
}

// admissionController is a generic admission rate limiter for both RouterInfos and LeaseSets.
// It enforces per-source introduction limits when cache pressure exceeds a threshold percentage.
type admissionController struct {
	mu       sync.Mutex
	capacity int
	sources  map[common.Hash]*sourceAdmissionWindow
	config   admissionConfig
}

// sourceAdmissionWindow tracks introductions from a single source within a time window.
type sourceAdmissionWindow struct {
	lastSeen      time.Time
	introductions map[common.Hash]time.Time
}

// newAdmissionController creates a generic admission controller with the given capacity and config.
func newAdmissionController(capacity int, config admissionConfig) *admissionController {
	return &admissionController{
		capacity: capacity,
		sources:  make(map[common.Hash]*sourceAdmissionWindow),
		config:   config,
	}
}

// SetCapacity updates the capacity used by pressure-based admission checks.
// Non-positive capacity values are ignored.
func (c *admissionController) SetCapacity(capacity int) {
	if capacity <= 0 {
		return
	}
	c.mu.Lock()
	c.capacity = capacity
	c.mu.Unlock()
}

// AllowIntroduction returns true when an introduction from source for key should be accepted
// under current admission pressure and per-source limits.
func (c *admissionController) AllowIntroduction(source *common.Hash, key common.Hash, currentCount int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.underPressure(currentCount) {
		return true
	}
	if source == nil {
		return false
	}

	now := time.Now()
	c.cleanupIfNeeded(now)

	window := c.sources[*source]
	if window == nil {
		window = &sourceAdmissionWindow{introductions: make(map[common.Hash]time.Time)}
		c.sources[*source] = window
	}

	window.lastSeen = now
	c.pruneWindow(window, now)

	if _, exists := window.introductions[key]; exists {
		window.introductions[key] = now
		return true
	}
	if len(window.introductions) >= c.config.perSource {
		return false
	}

	window.introductions[key] = now
	return true
}

// underPressure returns true if the cache is above the pressure threshold.
func (c *admissionController) underPressure(currentCount int) bool {
	if c.capacity <= 0 {
		return false
	}
	threshold := (c.capacity * c.config.pressurePct) / 100
	return currentCount >= threshold
}

// cleanupIfNeeded evicts stale sources if we're tracking too many.
func (c *admissionController) cleanupIfNeeded(now time.Time) {
	if len(c.sources) < c.config.trackedMax {
		return
	}

	// Find the oldest source and remove it
	var oldestKey common.Hash
	var oldestTime time.Time

	for key, window := range c.sources {
		if oldestTime.IsZero() || window.lastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = window.lastSeen
		}
	}

	delete(c.sources, oldestKey)
}

// pruneWindow removes introductions older than the window duration.
func (c *admissionController) pruneWindow(window *sourceAdmissionWindow, now time.Time) {
	for key, ts := range window.introductions {
		if now.Sub(ts) > c.config.window {
			delete(window.introductions, key)
		}
	}
}
