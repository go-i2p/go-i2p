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
// This function is thread-safe.
func RegisterCloser(c io.Closer) {
	closeMutex.Lock()
	defer closeMutex.Unlock()
	closeOnExit = append(closeOnExit, c)
	log.WithField("count", len(closeOnExit)).Debug("Registered closer")
}

// CloseAll closes all registered io.Closer instances and clears the list.
// This function is thread-safe.
func CloseAll() {
	closeMutex.Lock()
	defer closeMutex.Unlock()

	log.WithField("count", len(closeOnExit)).Debug("Closing all registered closers")

	for idx := range closeOnExit {
		if err := closeOnExit[idx].Close(); err != nil {
			log.WithError(err).Warn("Error closing resource")
		}
	}
	closeOnExit = nil
	log.Debug("All closers closed")
}
