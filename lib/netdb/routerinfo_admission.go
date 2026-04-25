package netdb

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
)

const (
	routerInfoAdmissionWindow      = time.Hour
	routerInfoPerSourceIntroduced  = 256
	routerInfoTrackedSourcesMax    = 2048
	routerInfoPressureThresholdPct = 80
)

type routerInfoAdmissionController struct {
	mu          sync.Mutex
	capacity    int
	sources     map[common.Hash]*sourceAdmissionWindow
	maxSources  int
	window      time.Duration
	perSource   int
	pressurePct int
}

type sourceAdmissionWindow struct {
	lastSeen      time.Time
	introductions map[common.Hash]time.Time
}

func newRouterInfoAdmissionController(capacity int) *routerInfoAdmissionController {
	return &routerInfoAdmissionController{
		capacity:    capacity,
		sources:     make(map[common.Hash]*sourceAdmissionWindow),
		maxSources:  routerInfoTrackedSourcesMax,
		window:      routerInfoAdmissionWindow,
		perSource:   routerInfoPerSourceIntroduced,
		pressurePct: routerInfoPressureThresholdPct,
	}
}

func (c *routerInfoAdmissionController) SetCapacity(capacity int) {
	if capacity <= 0 {
		return
	}
	c.mu.Lock()
	c.capacity = capacity
	c.mu.Unlock()
}

func (c *routerInfoAdmissionController) AllowIntroduction(source *common.Hash, key common.Hash, currentCount int) bool {
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

func (c *routerInfoAdmissionController) underPressure(currentCount int) bool {
	if c.capacity <= 0 {
		return false
	}
	return currentCount*100 >= c.capacity*c.pressurePct
}

func (c *routerInfoAdmissionController) deleteEmptyStaleSources(now time.Time) {
	for source, window := range c.sources {
		c.pruneWindow(window, now)
		if len(window.introductions) == 0 && now.Sub(window.lastSeen) > c.window {
			delete(c.sources, source)
		}
	}
}

func (c *routerInfoAdmissionController) deleteStaleSources(now time.Time) {
	for source, window := range c.sources {
		if now.Sub(window.lastSeen) > c.window {
			delete(c.sources, source)
		}
	}
}

func (c *routerInfoAdmissionController) cleanupIfNeeded(now time.Time) {
	if len(c.sources) <= c.maxSources {
		return
	}
	c.deleteEmptyStaleSources(now)
	if len(c.sources) <= c.maxSources {
		return
	}
	c.deleteStaleSources(now)
}

func (c *routerInfoAdmissionController) pruneWindow(window *sourceAdmissionWindow, now time.Time) {
	for key, ts := range window.introductions {
		if now.Sub(ts) > c.window {
			delete(window.introductions, key)
		}
	}
}
