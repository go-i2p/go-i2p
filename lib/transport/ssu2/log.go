package ssu2

import "github.com/go-i2p/logger"

var log = logger.GetGoI2PLogger()

// safeGo runs fn on a new goroutine with panic recovery. I2P-004: one-shot
// goroutines (e.g. an asynchronous session close) run with no upstream recover
// seam, so a panic in one would otherwise take down the whole router process.
// The panic is logged with the call site's name; the goroutine simply ends.
func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.WithFields(logger.Fields{"at": name, "panic": r}).
					Error("recovered from panic in one-shot goroutine")
			}
		}()
		fn()
	}()
}
