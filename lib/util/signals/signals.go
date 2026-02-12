package signals

import (
	"fmt"
	"os"
	"sync"
)

// sigChan is buffered to avoid missing signals delivered while no receiver is ready.
var sigChan = make(chan os.Signal, 1)

type Handler func()

var (
	mu           sync.RWMutex
	reloaders    []Handler
	interrupters []Handler
)

func RegisterReloadHandler(f Handler) {
	if f == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	reloaders = append(reloaders, f)
}

func handleReload() {
	mu.RLock()
	snapshot := make([]Handler, len(reloaders))
	copy(snapshot, reloaders)
	mu.RUnlock()
	for _, h := range snapshot {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// The signals package has no logger; write directly to stderr
					// so panicking handlers are visible in logs/console.
					fmt.Fprintf(os.Stderr, "signals: panic in reload handler: %v\n", r)
				}
			}()
			h()
		}()
	}
}

func RegisterInterruptHandler(f Handler) {
	if f == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	interrupters = append(interrupters, f)
}

func handleInterrupted() {
	mu.RLock()
	snapshot := make([]Handler, len(interrupters))
	copy(snapshot, interrupters)
	mu.RUnlock()
	for _, h := range snapshot {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// The signals package has no logger; write directly to stderr
					// so panicking handlers are visible in logs/console.
					fmt.Fprintf(os.Stderr, "signals: panic in interrupt handler: %v\n", r)
				}
			}()
			h()
		}()
	}
}
