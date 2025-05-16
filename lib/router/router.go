package router

import (
	"crypto/sha256"
	"strconv"
	"time"

	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/common/base32"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp"

	"github.com/go-i2p/logger"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
)

var log = logger.GetGoI2PLogger()

// i2p router type
type Router struct {
	// keystore for router info
	*keys.RouterInfoKeystore
	// multi-transport manager
	*transport.TransportMuxer
	// router configuration
	cfg *config.RouterConfig
	// netdb
	ndb netdb.StdNetDB
	// close channel
	closeChnl chan bool
	// running flag
	running bool
}

// CreateRouter creates a router with the provided configuration
func CreateRouter(cfg *config.RouterConfig) (*Router, error) {
	log.Debug("Creating router with provided configuration")
	r, err := FromConfig(cfg)
	if err != nil {
		log.WithError(err).Error("Failed to create router from configuration")
		return nil, err
	} else {
		log.Debug("Router created successfully with provided configuration")
	}
	r.RouterInfoKeystore, err = keys.NewRouterInfoKeystore(cfg.WorkingDir, "localRouter")
	log.Debug("Working directory is:", cfg.WorkingDir)
	if err != nil {
		log.WithError(err).Error("Failed to create RouterInfoKeystore")
		return nil, err
	} else {
		log.Debug("RouterInfoKeystore created successfully")
		if err = r.RouterInfoKeystore.StoreKeys(); err != nil {
			log.WithError(err).Error("Failed to store RouterInfoKeystore")
			return nil, err
		} else {
			log.Debug("RouterInfoKeystore stored successfully")
		}
	}
	pub, _, err := r.RouterInfoKeystore.GetKeys()
	if err != nil {
		log.WithError(err).Error("Failed to get keys from RouterInfoKeystore")
		return nil, err
	} else {
		// sha256 hash of public key
		pubHash := sha256.Sum256(pub.Bytes())
		b32PubHash := base32.EncodeToString(pubHash[:])
		log.Debug("Router public key hash:", b32PubHash)
	}

	ri, err := r.RouterInfoKeystore.ConstructRouterInfo(nil)
	if err != nil {
		log.WithError(err).Error("Failed to construct RouterInfo")
		return nil, err
	} else {
		log.Debug("RouterInfo constructed successfully")
		log.Debug("RouterInfo:", ri)
	}

	// we have our keystore and our routerInfo,, so now let's set up transports
	// add NTCP2 transport
	ntcp2, err := ntcp.NewNTCP2Transport(ri)
	if err != nil {
		log.WithError(err).Error("Failed to create NTCP2 transport")
		return nil, err
	} else {
		log.Debug("NTCP2 transport created successfully")
	}
	r.TransportMuxer = transport.Mux(ntcp2)
	ntcpaddr, err := ntcp2.Address()
	if err != nil {
		log.WithError(err).Error("Failed to get NTCP2 address")
		return nil, err
	} else {
		log.Debug("NTCP2 address:", ntcpaddr)
	}
	ri.AddAddress(ntcpaddr)

	// create a transport address

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
	if r.ndb.Size() < r.cfg.Bootstrap.LowPeerThreshold {
		log.Info("NetDB below threshold, initiating reseed")

		// Create a bootstrap instance
		bootstrapper := bootstrap.NewReseedBootstrap(r.cfg.Bootstrap)

		// Reseed the network database
		if err := r.ndb.Reseed(bootstrapper, r.cfg.Bootstrap.LowPeerThreshold); err != nil {
			log.WithError(err).Warn("Initial reseed failed, continuing with limited NetDB")
			// Continue anyway, we might have some peers
		}
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
