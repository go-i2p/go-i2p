package main

import (
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/router"
	"github.com/go-i2p/go-i2p/lib/util/signals"
	log "github.com/sirupsen/logrus"

	"flag"
)

func main() {
	netDbPath := flag.String("netDb", config.DefaultNetDbConfig.Path, "Path to the netDb")
	flag.Parse()
	config.RouterConfigProperties.NetDb.Path = *netDbPath
	go signals.Handle()
	log.Info("parsing i2p router configuration")
	log.Info("using netDb in:", config.RouterConfigProperties.NetDb.Path)
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
		r.Start()
		r.Wait()
		r.Close()
	} else {
		log.Errorf("failed to create i2p router: %s", err)
	}
}
