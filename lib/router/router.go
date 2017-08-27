package router

import (
	log "github.com/Sirupsen/logrus"
	"github.com/hkparker/go-i2p/lib/config"
	"github.com/hkparker/go-i2p/lib/netdb"
	"time"
)

// i2p router type
type Router struct {
	cfg       *config.RouterConfig
	ndb       netdb.StdNetDB
	closeChnl chan bool
}

// create router with default configuration
func CreateRouter() (r *Router, err error) {
	cfg := config.DefaultRouterConfig
	r, err = FromConfig(cfg)
	return
}

// create router from configuration
func FromConfig(c *config.RouterConfig) (r *Router, err error) {
	r = new(Router)
	r.cfg = c
	r.closeChnl = make(chan bool)
	return
}

func (r *Router) Wait() {
	<-r.closeChnl
}

func (r *Router) Stop() {
	r.closeChnl <- true
}

func (r *Router) Close() error {
	return nil
}

// run i2p router mainloop
func (r *Router) Run() {
	r.ndb = netdb.StdNetDB(r.cfg.NetDb.Path)
	// make sure the netdb is ready
	err := r.ndb.Ensure()
	if err == nil {
		// netdb ready
		log.WithFields(log.Fields{
			"at": "(Router) Run",
		}).Info("Router ready")
		for err == nil {
			time.Sleep(time.Second)
		}
	} else {
		// netdb failed
		log.WithFields(log.Fields{
			"at":     "(Router) Run",
			"reason": err.Error(),
		}).Error("Netdb Startup failed")
	}
}
