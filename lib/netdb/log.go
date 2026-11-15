package netdb

import "github.com/go-i2p/logger"

var log = logger.GetGoI2PLogger()

// shortHash returns up to the first n characters of s for safe use in log
// messages. If s is shorter than n, the entire string is returned. This
// prevents panics from slice-bounds-out-of-range when hash.String() returns
// an unexpectedly short representation (e.g., zero-value hash).
func shortHash(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

// logAt returns a logger.Entry with the "at" field pre-set to the given
// location string (typically the method name). This helper reduces boilerplate
// in log calls and ensures consistent "at" field formatting across the netdb
// package. Usage: logAt("MethodName").Debug("message")
func logAt(at string) *logger.Entry {
	return log.WithFields(logger.Fields{"at": at})
}

// safeGo runs fn on a new goroutine with panic recovery. These goroutines
// (exploration, Kademlia lookups, prefetching) parse and act on untrusted
// network data with no upstream recover seam, so a panic in one would
// otherwise take down the whole router process. The panic is logged with the
// call site's name; the goroutine simply ends. Callers whose goroutine feeds a
// WaitGroup or an exact-count channel collector must keep their own
// wg.Done()/send defers inside fn so the join cannot hang on a recovered panic.
func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logAt(name).WithField("panic", r).
					Error("recovered from panic in netdb goroutine")
			}
		}()
		fn()
	}()
}
