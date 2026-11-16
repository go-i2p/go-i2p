package router

import "github.com/go-i2p/logger"

var log = logger.GetGoI2PLogger()

// logAt returns a logger.Entry with the "at" field pre-set to the given
// location string (typically the method name). This helper reduces boilerplate
// in log calls and ensures consistent "at" field formatting across the router
// package. Usage: logAt("MethodName").Debug("message")
func logAt(at string) *logger.Entry {
	return log.WithFields(logger.Fields{"at": at})
}

// safeGo runs fn on a new goroutine with panic recovery. A panic in a
// Go-spawned child goroutine has no upstream recover seam, so it would
// otherwise take down the whole router process. The panic is logged with the
// call site's name; the goroutine simply ends. This mirrors the convention in
// the transport, netdb and i2pcontrol packages.
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

// recoverGoroutine recovers a panic from a long-lived loop iteration and logs
// it, so one bad message cannot crash the router or wedge the loop. Call it via
// "defer recoverGoroutine(at)" inside each iteration body.
func recoverGoroutine(at string) {
	if r := recover(); r != nil {
		logAt(at).WithField("panic", r).
			Error("recovered from panic in router goroutine; continuing loop")
	}
}
