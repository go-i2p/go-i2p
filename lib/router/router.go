package router

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/go-i2p/common/base32"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/i2np"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"

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
	// netdb
	*netdb.StdNetDB
	// message router for processing I2NP messages
	messageRouter *i2np.MessageRouter
	// router configuration
	cfg *config.RouterConfig
	// close channel
	closeChnl chan bool
	// running flag and mutex for thread-safe access
	running bool
	runMux  sync.RWMutex
}

// CreateRouter creates a router with the provided configuration
func CreateRouter(cfg *config.RouterConfig) (*Router, error) {
	log.Debug("Creating router with provided configuration")

	r, err := FromConfig(cfg)
	if err != nil {
		log.WithError(err).Error("Failed to create router from configuration")
		return nil, err
	}
	log.Debug("Router created successfully with provided configuration")

	if err := initializeRouterKeystore(r, cfg); err != nil {
		return nil, err
	}

	if err := validateRouterKeys(r); err != nil {
		return nil, err
	}

	ri, err := constructRouterInfo(r)
	if err != nil {
		return nil, err
	}

	if err := setupNTCP2Transport(r, ri); err != nil {
		return nil, err
	}

	return r, nil
}

// initializeRouterKeystore creates and stores the router keystore
func initializeRouterKeystore(r *Router, cfg *config.RouterConfig) error {
	log.Debug("Working directory is:", cfg.WorkingDir)

	keystore, err := keys.NewRouterInfoKeystore(cfg.WorkingDir, "localRouter")
	if err != nil {
		log.WithError(err).Error("Failed to create RouterInfoKeystore")
		return err
	}
	log.Debug("RouterInfoKeystore created successfully")

	if err = keystore.StoreKeys(); err != nil {
		log.WithError(err).Error("Failed to store RouterInfoKeystore")
		return err
	}
	log.Debug("RouterInfoKeystore stored successfully")

	r.RouterInfoKeystore = keystore
	return nil
}

// validateRouterKeys extracts and validates the router's public key
func validateRouterKeys(r *Router) error {
	pub, _, err := r.RouterInfoKeystore.GetKeys()
	if err != nil {
		log.WithError(err).Error("Failed to get keys from RouterInfoKeystore")
		return err
	}

	// sha256 hash of public key
	pubHash := sha256.Sum256(pub.Bytes())
	b32PubHash := base32.EncodeToString(pubHash[:])
	log.Debug("Router public key hash:", b32PubHash)

	return nil
}

// constructRouterInfo builds the router info from the keystore
func constructRouterInfo(r *Router) (*router_info.RouterInfo, error) {
	ri, err := r.RouterInfoKeystore.ConstructRouterInfo(nil)
	if err != nil {
		log.WithError(err).Error("Failed to construct RouterInfo")
		return nil, err
	}

	log.Debug("RouterInfo constructed successfully")
	log.Debug("RouterInfo:", ri)
	return ri, nil
}

// setupNTCP2Transport configures and initializes the NTCP2 transport layer
func setupNTCP2Transport(r *Router, ri *router_info.RouterInfo) error {
	// add NTCP2 transport
	ntcp2Config, err := ntcp.NewConfig(":0") // Use port 0 for automatic assignment
	if err != nil {
		log.WithError(err).Error("Failed to create NTCP2 config")
		return err
	}

	ntcp2Transport, err := ntcp.NewNTCP2Transport(*ri, ntcp2Config)
	if err != nil {
		log.WithError(err).Error("Failed to create NTCP2 transport")
		return err
	}
	log.Debug("NTCP2 transport created successfully")

	r.TransportMuxer = transport.Mux(ntcp2Transport)
	ntcpaddr := ntcp2Transport.Addr()
	if ntcpaddr == nil {
		log.Error("Failed to get NTCP2 address")
		return errors.New("failed to get NTCP2 address")
	}
	log.Debug("NTCP2 address:", ntcpaddr)

	// TODO: Add the NTCP2 address to RouterInfo once RouterAddress conversion is implemented
	// ri.AddAddress(ntcpaddr)

	return nil
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
	r.runMux.Lock()
	defer r.runMux.Unlock()

	if !r.running {
		log.Debug("Router already stopped")
		return
	}

	r.running = false

	// Send close signal without blocking - use select with default case
	select {
	case r.closeChnl <- true:
		log.Debug("Router stop signal sent")
	default:
		log.Debug("Router stop signal already sent or channel full")
	}
}

// Close closes any internal state and finalizes router resources so that nothing can start up again
func (r *Router) Close() error {
	log.Warn("Closing router not implemented(?)")
	return nil
}

// Start starts router mainloop
func (r *Router) Start() {
	r.runMux.Lock()
	defer r.runMux.Unlock()

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

// initializeNetDB creates and configures the network database
func (r *Router) initializeNetDB() error {
	log.Debug("Entering router mainloop")
	r.StdNetDB = netdb.NewStdNetDB(r.cfg.NetDb.Path)
	log.WithField("netdb_path", r.cfg.NetDb.Path).Debug("Created StdNetDB")
	return nil
}

// initializeMessageRouter sets up message routing with NetDB integration
func (r *Router) initializeMessageRouter() {
	messageConfig := i2np.MessageRouterConfig{
		MaxRetries:     3,
		DefaultTimeout: 30 * time.Second,
		EnableLogging:  true,
	}
	r.messageRouter = i2np.NewMessageRouter(messageConfig)
	r.messageRouter.SetNetDB(r.StdNetDB)
	r.messageRouter.SetPeerSelector(r.StdNetDB)
	log.Debug("Message router initialized with NetDB integration and peer selection")
}

// ensureNetDBReady validates NetDB state and performs reseed if needed
func (r *Router) ensureNetDBReady() error {
	if err := r.StdNetDB.Ensure(); err != nil {
		log.WithError(err).Error("Failed to ensure NetDB")
		return err
	}

	if sz := r.StdNetDB.Size(); sz >= 0 {
		log.WithField("size", sz).Debug("NetDB Size: " + strconv.Itoa(sz))
	} else {
		log.Warn("Unable to determine NetDB size")
	}

	if r.StdNetDB.Size() < r.cfg.Bootstrap.LowPeerThreshold {
		return r.performReseed()
	}
	return nil
}

// performReseed executes network database reseeding process
func (r *Router) performReseed() error {
	log.Info("NetDB below threshold, initiating reseed")

	bootstrapper := bootstrap.NewReseedBootstrap(r.cfg.Bootstrap)

	if err := r.StdNetDB.Reseed(bootstrapper, r.cfg.Bootstrap.LowPeerThreshold); err != nil {
		log.WithError(err).Warn("Initial reseed failed, continuing with limited NetDB")
		return err
	}
	return nil
}

// runMainLoop executes the primary router event loop
func (r *Router) runMainLoop() {
	log.WithFields(logrus.Fields{
		"at": "(Router) mainloop",
	}).Debug("Router ready with database message processing enabled")

	for {
		r.runMux.RLock()
		shouldRun := r.running
		r.runMux.RUnlock()

		if !shouldRun {
			break
		}

		select {
		case <-r.closeChnl:
			log.Debug("Router received close signal in mainloop")
			return
		case <-time.After(time.Second):
			// Continue loop after 1 second timeout
		}
	}
}

// run i2p router mainloop
func (r *Router) mainloop() {
	if err := r.initializeNetDB(); err != nil {
		log.WithError(err).Error("Failed to initialize NetDB")
		r.Stop()
		return
	}

	r.initializeMessageRouter()

	if err := r.ensureNetDBReady(); err != nil {
		log.WithFields(logrus.Fields{
			"at":     "(Router) mainloop",
			"reason": err.Error(),
		}).Error("Netdb Startup failed")
		r.Stop()
		return
	}

	r.runMainLoop()
	log.Debug("Exiting router mainloop")
}
