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
	r.startPeriodicTask("startHealthMonitor", defaultHealthCheckInterval, func() {
		r.logHealthMetrics()
	})
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
//
// Note: This function provides degraded observability on non-Linux systems.
// The -1 sentinel indicates that FD counting is not available on the current platform.
// For production monitoring on macOS/BSD, consider alternative approaches such as
// ulimit inspection via shell subprocess or platform-specific system calls.
func countOpenFDs() int {
	if runtime.GOOS != "linux" {
		return -1
	}
	entries, err := os.ReadDir(filepath.Join("/proc", "self", "fd"))
	if err != nil {
		return -1
	}
	return len(entries)
}
