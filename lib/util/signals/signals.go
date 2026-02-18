package signals

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
)

// sigChan is buffered to avoid missing signals delivered while no receiver is ready.
var sigChan = make(chan os.Signal, 1)

// Handler is a function called when a signal is received.
type Handler func()

// HandlerID is a unique identifier returned by registration functions,
// used to deregister individual handlers.
type HandlerID int

// registeredHandler pairs a handler with its unique ID.
type registeredHandler struct {
	id HandlerID
	fn Handler
}

var (
	mu           sync.RWMutex
	reloaders    []registeredHandler
	interrupters []registeredHandler
	nextID       HandlerID
	stopOnce     sync.Once
)

// RegisterReloadHandler registers a handler called on SIGHUP (config reload).
// Returns a HandlerID that can be passed to DeregisterReloadHandler.
// Nil handlers are silently ignored and return -1.
func RegisterReloadHandler(f Handler) HandlerID {
	if f == nil {
		return -1
	}
	mu.Lock()
	defer mu.Unlock()
	id := nextID
	nextID++
	reloaders = append(reloaders, registeredHandler{id: id, fn: f})
	return id
}

// DeregisterReloadHandler removes a previously registered reload handler by ID.
func DeregisterReloadHandler(id HandlerID) {
	mu.Lock()
	defer mu.Unlock()
	for i, h := range reloaders {
		if h.id == id {
			reloaders = append(reloaders[:i], reloaders[i+1:]...)
			return
		}
	}
}

func handleReload() {
	mu.RLock()
	snapshot := make([]registeredHandler, len(reloaders))
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
			h.fn()
		}()
	}
}

// RegisterInterruptHandler registers a handler called on SIGINT/SIGTERM (shutdown).
// Returns a HandlerID that can be passed to DeregisterInterruptHandler.
// Nil handlers are silently ignored and return -1.
func RegisterInterruptHandler(f Handler) HandlerID {
	if f == nil {
		return -1
	}
	mu.Lock()
	defer mu.Unlock()
	id := nextID
	nextID++
	interrupters = append(interrupters, registeredHandler{id: id, fn: f})
	return id
}

// DeregisterInterruptHandler removes a previously registered interrupt handler by ID.
func DeregisterInterruptHandler(id HandlerID) {
	mu.Lock()
	defer mu.Unlock()
	for i, h := range interrupters {
		if h.id == id {
			interrupters = append(interrupters[:i], interrupters[i+1:]...)
			return
		}
	}
}

func handleInterrupted() {
	mu.RLock()
	snapshot := make([]registeredHandler, len(interrupters))
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
			h.fn()
		}()
	}
}

// StopHandle closes the signal channel, causing Handle() to return.
// It first calls signal.Stop to prevent signal delivery to the closed channel.
// Safe to call multiple times; only the first call takes effect.
func StopHandle() {
	stopOnce.Do(func() {
		signal.Stop(sigChan)
		close(sigChan)
	})
}
