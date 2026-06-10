package netdb

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
)

const (
	leaseSetAdmissionWindow      = time.Hour
	leaseSetPerSourceIntroduced  = 256
	leaseSetTrackedSourcesMax    = 2048
	leaseSetPressureThresholdPct = 80
)

type leaseSetAdmissionController struct {
	mu          sync.Mutex
	capacity    int
	sources     map[common.Hash]*sourceAdmissionWindow
	maxSources  int
	window      time.Duration
	perSource   int
	pressurePct int
}

func newLeaseSetAdmissionController(capacity int) *leaseSetAdmissionController {
	return &leaseSetAdmissionController{
		capacity:    capacity,
		sources:     make(map[common.Hash]*sourceAdmissionWindow),
		maxSources:  leaseSetTrackedSourcesMax,
		window:      leaseSetAdmissionWindow,
		perSource:   leaseSetPerSourceIntroduced,
		pressurePct: leaseSetPressureThresholdPct,
	}
}

// SetCapacity updates the LeaseSet capacity used by pressure-based admission checks.
// Non-positive capacity values are ignored.
func (c *leaseSetAdmissionController) SetCapacity(capacity int) {
	if capacity <= 0 {
		return
	}
	c.mu.Lock()
	c.capacity = capacity
	c.mu.Unlock()
}

// AllowIntroduction returns true when a LeaseSet introduction from source for
// key should be accepted under current admission pressure and per-source limits.
func (c *leaseSetAdmissionController) AllowIntroduction(source *common.Hash, key common.Hash, currentCount int) bool {
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
	if len(window.introductions) >= c.perSource {
		return false
	}

	window.introductions[key] = now
	return true
}

func (c *leaseSetAdmissionController) underPressure(currentCount int) bool {
	if c.capacity <= 0 {
		return false
	}
	return currentCount*100 >= c.capacity*c.pressurePct
}

func (c *leaseSetAdmissionController) deleteEmptyStaleSources(now time.Time) {
	for source, window := range c.sources {
		c.pruneWindow(window, now)
		if len(window.introductions) == 0 && now.Sub(window.lastSeen) > c.window {
			delete(c.sources, source)
		}
	}
}

func (c *leaseSetAdmissionController) deleteStaleSources(now time.Time) {
	for source, window := range c.sources {
		if now.Sub(window.lastSeen) > c.window {
			delete(c.sources, source)
		}
	}
}

func (c *leaseSetAdmissionController) cleanupIfNeeded(now time.Time) {
	if len(c.sources) <= c.maxSources {
		return
	}
	c.deleteEmptyStaleSources(now)
	if len(c.sources) <= c.maxSources {
		return
	}
	c.deleteStaleSources(now)
}

func (c *leaseSetAdmissionController) pruneWindow(window *sourceAdmissionWindow, now time.Time) {
	for key, ts := range window.introductions {
		if now.Sub(ts) > c.window {
			delete(window.introductions, key)
		}
	}
}
