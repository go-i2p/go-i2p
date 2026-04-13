package router

import (
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/go-i2p/logger"
)

const defaultHealthCheckInterval = 60 * time.Second

// startHealthMonitor launches a background goroutine that periodically logs
// resource usage metrics (goroutine count, active session count, open file
// descriptors on Linux). This provides runtime visibility into potential
// slow resource leaks for a long-running router process.
func (r *Router) startHealthMonitor() {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(defaultHealthCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-ticker.C:
				r.logHealthMetrics()
			}
		}
	}()
	log.WithField("at", "startHealthMonitor").Debug("health monitor started")
}

// logHealthMetrics collects and logs current resource usage.
func (r *Router) logHealthMetrics() {
	goroutines := runtime.NumGoroutine()

	r.sessionMutex.RLock()
	sessions := len(r.activeSessions)
	r.sessionMutex.RUnlock()

	fds := countOpenFDs()

	log.WithFields(logger.Fields{
		"at":         "healthMonitor",
		"goroutines": goroutines,
		"sessions":   sessions,
		"open_fds":   fds,
	}).Debug("resource health check")
}

// countOpenFDs returns the number of open file descriptors for the current
// process on Linux (via /proc/self/fd). Returns -1 on non-Linux platforms.
func countOpenFDs() int {
	entries, err := os.ReadDir(filepath.Join("/proc", "self", "fd"))
	if err != nil {
		return -1
	}
	return len(entries)
}
