//go:build !windows
// +build !windows

package signals

import (
	"os/signal"
	"sync"
	"syscall"
)

// signalOnce ensures signal.Notify is called exactly once, when Handle()
// is first invoked. This avoids intercepting signals at import time,
// which would silently swallow SIGINT/SIGTERM from tests and tools
// that import this package without intending to handle signals.
var signalOnce sync.Once

func Handle() {
	// Register signal handlers on first call (not at import time).
	signalOnce.Do(func() {
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	})
	for {
		sig, ok := <-sigChan
		if !ok {
			// closed channel
			return
		}
		if sig == syscall.SIGHUP {
			handleReload()
		} else if sig == syscall.SIGINT || sig == syscall.SIGTERM {
			handlePreShutdown()
			handleInterrupted()
		}
		// Note: other signals intentionally ignored
	}
}
