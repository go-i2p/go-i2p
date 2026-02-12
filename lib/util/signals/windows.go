//go:build windows
// +build windows

package signals

import (
	"os"
	"os/signal"
	"sync"
)

// signalOnce ensures signal.Notify is called exactly once, when Handle()
// is first invoked. This avoids intercepting signals at import time,
// which would silently swallow os.Interrupt from tests and tools
// that import this package without intending to handle signals.
var signalOnce sync.Once

func Handle() {
	// Register signal handlers on first call (not at import time).
	signalOnce.Do(func() {
		signal.Notify(sigChan, os.Interrupt)
	})
	for {
		sig, ok := <-sigChan
		if !ok {
			// closed channel
			return
		}
		if sig == os.Interrupt {
			handleInterrupted()
		}
		// Note: other signals intentionally ignored on Windows
	}
}
