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

// CloseAll closes all registered io.Closer instances and clears the list.
// This function is thread-safe. The list is copied under the lock, then
// each closer is closed outside the lock to prevent slow Close() calls
// from blocking RegisterCloser() or other callers.
func CloseAll() {
	closeMutex.Lock()
	// Copy the slice and clear the original under the lock
	closers := make([]io.Closer, len(closeOnExit))
	copy(closers, closeOnExit)
	closeOnExit = nil
	closeMutex.Unlock()

	log.WithField("count", len(closers)).Debug("Closing all registered closers")

	for idx := range closers {
		if err := closers[idx].Close(); err != nil {
			log.WithError(err).Warn("Error closing resource")
		}
	}
	log.Debug("All closers closed")
}
