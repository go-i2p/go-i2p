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
}

// CloseAll closes all registered io.Closer instances and clears the list.
// This function is thread-safe.
func CloseAll() {
	closeMutex.Lock()
	defer closeMutex.Unlock()

	for idx := range closeOnExit {
		closeOnExit[idx].Close()
	}
	closeOnExit = nil
}
