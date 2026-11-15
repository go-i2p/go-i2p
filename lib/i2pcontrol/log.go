package i2pcontrol

import "github.com/go-i2p/logger"

var log = logger.GetGoI2PLogger()

// safeGo runs fn on a new goroutine with panic recovery. These goroutines
// (request handling, reseed, graceful stop, HTTP serve) run with no upstream
// recover seam, so a panic in one would otherwise take down the whole router
// process. The panic is logged with the call site's name; the goroutine simply
// ends. Callers whose goroutine feeds a WaitGroup must keep their own wg.Done()
// defer inside fn so the join cannot hang on a recovered panic.
func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.WithFields(logger.Fields{"at": name}).WithField("panic", r).
					Error("recovered from panic in i2pcontrol goroutine")
			}
		}()
		fn()
	}()
}
