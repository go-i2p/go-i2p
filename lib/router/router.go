package router

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/netdb"
	log "github.com/sirupsen/logrus"
)

// i2p router type
type Router struct {
	cfg       *config.RouterConfig
	ndb       netdb.StdNetDB
	closeChnl chan bool
	running   bool
}

// create router with default configuration
func CreateRouter() (r *Router, err error) {
	cfg := config.RouterConfigProperties
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

// Wait blocks until router is fully stopped
func (r *Router) Wait() {
	<-r.closeChnl
}

// Stop starts stopping internal state of router
func (r *Router) Stop() {
	r.closeChnl <- true
	r.running = false
}

// Close closes any internal state and finallizes router resources so that nothing can start up again
func (r *Router) Close() error {
	return nil
}

// Start starts router mainloop
func (r *Router) Start() {
	if r.running {
		log.WithFields(log.Fields{
			"at":     "(Router) Start",
			"reason": "router is already running",
		}).Error("Error Starting router")
		return
	}
	r.running = true
	go r.mainloop()
}

// run i2p router mainloop
func (r *Router) mainloop() {
	r.ndb = netdb.NewStdNetDB(r.cfg.NetDb.Path)
	// make sure the netdb is ready
	var e error
	if err := r.ndb.Ensure(); err != nil {
		e = err
	}
	if sz := r.ndb.Size(); sz >= 0 {
		log.Info("NetDB Size:", sz)
	}
	if e == nil {
		// netdb ready
		log.WithFields(log.Fields{
			"at": "(Router) mainloop",
		}).Info("Router ready")
		for e == nil {
			time.Sleep(time.Second)
		}
	} else {
		// netdb failed
		log.WithFields(log.Fields{
			"at":     "(Router) mainloop",
			"reason": e.Error(),
		}).Error("Netdb Startup failed")
		r.Stop()
	}
}
