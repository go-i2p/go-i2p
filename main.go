package main

import (
	log "github.com/Sirupsen/logrus"
	"github.com/hkparker/go-i2p/lib/router"
	"github.com/hkparker/go-i2p/lib/util/signals"
)

func main() {
	go signals.Handle()
	log.Info("parsing i2p router configuration")

	log.Info("starting up i2p router")
	r, err := router.CreateRouter()
	if err == nil {
		signals.RegisterReloadHandler(func() {
			// TODO: reload config
		})
		signals.RegisterInterruptHandler(func() {
			// TODO: graceful shutdown
			r.Stop()
		})
		go r.Run()
		defer r.Close()
		r.Wait()
	} else {
		log.Errorf("failed to create i2p router: %s", err)
	}
}
