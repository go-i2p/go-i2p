package transport

import "github.com/go-i2p/logger"

var log = logger.GetGoI2PLogger()

// logAt returns a logger.Entry with the "at" field pre-set to the given
// location string (typically the method name). This helper reduces boilerplate
// in log calls and ensures consistent "at" field formatting across the transport
// package. Usage: logAt("MethodName").Debug("message")
func logAt(at string) *logger.Entry {
	return log.WithFields(logger.Fields{"at": at})
}

// safeGo runs fn on a new goroutine with panic recovery. I2P-004: one-shot
// goroutines run with no upstream recover seam, so a panic in one would
// otherwise take down the whole router process. The panic is logged with the
// call site's name; the goroutine simply ends.
func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logAt(name).WithField("panic", r).
					Error("recovered from panic in one-shot goroutine")
			}
		}()
		fn()
	}()
}
