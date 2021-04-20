package signals

import (
	"os"
)

var sigChan = make(chan os.Signal)

type Handler func()

var reloaders []Handler

func RegisterReloadHandler(f Handler) {
	reloaders = append(reloaders, f)
}

func handleReload() {
	for idx := range reloaders {
		reloaders[idx]()
	}
}

var interrupters []Handler

func RegisterInterruptHandler(f Handler) {
	interrupters = append(interrupters, f)
}

func handleInterrupted() {
	for idx := range interrupters {
		interrupters[idx]()
	}
}
