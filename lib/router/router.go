package router

import (
	"strconv"
	"time"

	"github.com/go-i2p/logger"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/netdb"
)

var log = logger.GetGoI2PLogger()

// i2p router type
type Router struct {
	cfg       *config.RouterConfig
	ndb       netdb.StdNetDB
	closeChnl chan bool
	running   bool
}

// CreateRouter creates a router with the provided configuration
func CreateRouter(cfg *config.RouterConfig) (*Router, error) {
	log.Debug("Creating router with provided configuration")
	r, err := FromConfig(cfg)
	if err != nil {
		log.WithError(err).Error("Failed to create router from configuration")
	} else {
		log.Debug("Router created successfully with provided configuration")
	}
	return r, err
}

// create router from configuration
func FromConfig(c *config.RouterConfig) (r *Router, err error) {
	log.WithField("config", c).Debug("Creating router from configuration")
	r = new(Router)
	r.cfg = c
	r.closeChnl = make(chan bool)
	log.Debug("Router created successfully from configuration")
	return
}

// Wait blocks until router is fully stopped
func (r *Router) Wait() {
	log.Debug("Waiting for router to stop")
	<-r.closeChnl
	log.Debug("Router has stopped")
}

// Stop starts stopping internal state of router
func (r *Router) Stop() {
	log.Debug("Stopping router")
	r.closeChnl <- true
	r.running = false
	log.Debug("Router stop signal sent")
}

// Close closes any internal state and finallizes router resources so that nothing can start up again
func (r *Router) Close() error {
	log.Warn("Closing router not implemented(?)")
	return nil
}

// Start starts router mainloop
func (r *Router) Start() {
	if r.running {
		log.WithFields(logrus.Fields{
			"at":     "(Router) Start",
			"reason": "router is already running",
		}).Error("Error Starting router")
		return
	}
	log.Debug("Starting router")
	r.running = true
	go r.mainloop()
}

// run i2p router mainloop
func (r *Router) mainloop() {
	log.Debug("Entering router mainloop")
	r.ndb = netdb.NewStdNetDB(r.cfg.NetDb.Path)
	log.WithField("netdb_path", r.cfg.NetDb.Path).Debug("Created StdNetDB")
	// make sure the netdb is ready
	var e error
	if err := r.ndb.Ensure(); err != nil {
		e = err
		log.WithError(err).Error("Failed to ensure NetDB")
	}
	if sz := r.ndb.Size(); sz >= 0 {
		log.WithField("size", sz).Debug("NetDB Size: " + strconv.Itoa(sz))
	} else {
		log.Warn("Unable to determine NetDB size")
	}
	if e == nil {
		// netdb ready
		log.WithFields(logrus.Fields{
			"at": "(Router) mainloop",
		}).Debug("Router ready")
		for e == nil {
			time.Sleep(time.Second)
		}
	} else {
		// netdb failed
		log.WithFields(logrus.Fields{
			"at":     "(Router) mainloop",
			"reason": e.Error(),
		}).Error("Netdb Startup failed")
		r.Stop()
	}
	log.Debug("Exiting router mainloop")
}
