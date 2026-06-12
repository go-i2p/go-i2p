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
