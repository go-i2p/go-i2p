package util

import (
	"io"
	"sync"
)

var (
	closeOnExit []io.Closer
	closeMutex  sync.Mutex
)

// RegisterCloser registers an io.Closer to be closed during shutdown.
// Nil closers are silently ignored to prevent panics in CloseAll.
// This function is thread-safe.
func RegisterCloser(c io.Closer) {
	if c == nil {
		return
	}
	closeMutex.Lock()
	defer closeMutex.Unlock()
	closeOnExit = append(closeOnExit, c)
	log.WithField("count", len(closeOnExit)).Debug("Registered closer")
}

// CloseAll closes all registered io.Closer instances in reverse (LIFO) order
// and clears the list. LIFO ordering ensures resources are released in the
// opposite order of their registration, which is important when later resources
// depend on earlier ones. Each closer is protected by recover() to prevent one
// panicking closer from aborting the remaining closers.
// This function is thread-safe.
func CloseAll() {
	closeMutex.Lock()
	// Copy the slice and clear the original under the lock
	closers := make([]io.Closer, len(closeOnExit))
	copy(closers, closeOnExit)
	closeOnExit = nil
	closeMutex.Unlock()

	log.WithField("count", len(closers)).Debug("Closing all registered closers (LIFO order)")

	// Close in reverse (LIFO) order
	for i := len(closers) - 1; i >= 0; i-- {
		func(c io.Closer) {
			defer func() {
				if r := recover(); r != nil {
					log.WithField("panic", r).Warn("Panic while closing resource")
				}
			}()
			if err := c.Close(); err != nil {
				log.WithError(err).Warn("Error closing resource")
			}
		}(closers[i])
	}
	log.Debug("All closers closed")
}
