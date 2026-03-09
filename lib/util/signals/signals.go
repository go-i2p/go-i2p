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

// registerHandler appends a handler to the given slice and returns its unique ID.
// Nil handlers are silently ignored and return -1.
func registerHandler(f Handler, handlers *[]registeredHandler) HandlerID {
	if f == nil {
		return -1
	}
	mu.Lock()
	defer mu.Unlock()
	id := nextID
	nextID++
	*handlers = append(*handlers, registeredHandler{id: id, fn: f})
	return id
}

// deregisterHandler removes a handler by ID from the given slice.
func deregisterHandler(id HandlerID, handlers *[]registeredHandler) {
	mu.Lock()
	defer mu.Unlock()
	for i, h := range *handlers {
		if h.id == id {
			*handlers = append((*handlers)[:i], (*handlers)[i+1:]...)
			return
		}
	}
}

// RegisterReloadHandler registers a handler called on SIGHUP (config reload).
// Returns a HandlerID that can be passed to DeregisterReloadHandler.
// Nil handlers are silently ignored and return -1.
func RegisterReloadHandler(f Handler) HandlerID {
	return registerHandler(f, &reloaders)
}

// DeregisterReloadHandler removes a previously registered reload handler by ID.
func DeregisterReloadHandler(id HandlerID) {
	deregisterHandler(id, &reloaders)
}

// runHandlers takes a snapshot of the given handler slice under the read lock
// and invokes each handler, recovering from panics. kind is used in panic messages.
func runHandlers(handlers []registeredHandler, kind string) {
	mu.RLock()
	snapshot := make([]registeredHandler, len(handlers))
	copy(snapshot, handlers)
	mu.RUnlock()
	for _, h := range snapshot {
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "signals: panic in %s handler: %v\n", kind, r)
				}
			}()
			h.fn()
		}()
	}
}

func handleReload() {
	runHandlers(reloaders, "reload")
}

// RegisterInterruptHandler registers a handler called on SIGINT/SIGTERM (shutdown).
// Returns a HandlerID that can be passed to DeregisterInterruptHandler.
// Nil handlers are silently ignored and return -1.
func RegisterInterruptHandler(f Handler) HandlerID {
	return registerHandler(f, &interrupters)
}

// DeregisterInterruptHandler removes a previously registered interrupt handler by ID.
func DeregisterInterruptHandler(id HandlerID) {
	deregisterHandler(id, &interrupters)
}

func handleInterrupted() {
	runHandlers(interrupters, "interrupt")
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
