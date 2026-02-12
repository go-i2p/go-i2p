package signals

import (
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
					// Log would be better but signals package has no logger;
					// at minimum, prevent one panicking handler from aborting
					// all remaining handlers.
				}
			}()
			h()
		}()
	}
}

func RegisterInterruptHandler(f Handler) {
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
					// Prevent one panicking handler from aborting
					// all remaining handlers.
				}
			}()
			h()
		}()
	}
}
