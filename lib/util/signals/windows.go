//go:build windows
// +build windows

package signals

import (
	"os"
	"os/signal"
)

func init() {
	signal.Notify(sigChan, os.Interrupt)
}

func Handle() {
	for {
		sig, ok := <-sigChan
		if !ok {
			// closed channel
			return
		}
		if sig == os.Interrupt {
			handleInterrupted()
		} else {
			// wtf?
		}
	}

}
