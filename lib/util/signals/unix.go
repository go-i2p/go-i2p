// +build !windows

package signals

import (
	"os/signal"
	"syscall"
)

func init() {
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
}

func Handle() {
	for {
		sig, ok := <-sigChan
		if !ok {
			// closed channel
			return
		}
		if sig == syscall.SIGHUP {
			handleReload()
		} else if sig == syscall.SIGINT || sig == syscall.SIGTERM {
			handleInterrupted()
		} else {
			// wtf?
		}
	}

}
