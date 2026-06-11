package router

import (
	"context"
	"encoding/base64"
	"strings"
	"sync"

	"github.com/go-i2p/common/base32"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Router is the core I2P router implementation that manages transports, the network database,
// tunnel pools, and message routing for participating in the I2P network.
type Router struct {
	// keystore for router info
	keystore *keys.RouterInfoKeystore
	// multi-transport manager
	transports *transport.TransportMuxer
	// netdb
	netdb *netdb.StdNetDB
	// message router for processing I2NP messages
	messageRouter *i2np.I2NPMessageDispatcher
	// garlic message router for handling non-LOCAL garlic clove forwarding
	garlicRouter *GarlicMessageRouter
	// router configuration
	cfg *config.RouterConfig
	// close channel
	closeChnl chan bool
	// wg tracks goroutine completion for clean shutdown
	wg sync.WaitGroup
	// running flag and mutex for thread-safe access
	running bool
	runMux  sync.RWMutex

	// ctx is the router's lifecycle context, cancelled when Stop() is called
	ctx context.Context
	// cancel cancels the router's context, triggering graceful shutdown
	cancel context.CancelFunc

	// Session tracking for transport message routing (NTCP2 and SSU2)
	activeSessions map[common.Hash]transport.TransportSession
	// sessionMutex protects concurrent access to activeSessions map
	sessionMutex sync.RWMutex

	// I2CP server for client applications
	i2cpServer *i2cp.Server

	// tunnelManager manages tunnel building and pool maintenance
	tunnelManager i2np.TunnelOrchestrator

	// participantManager tracks tunnels where this router acts as a transit hop
	participantManager *tunnel.ParticipantManager

	// i2pcontrolServer provides RPC monitoring interface
	i2pcontrolServer I2PControlServer

	// bandwidthTracker tracks bandwidth usage and calculates rolling averages
	bandwidthTracker *BandwidthTracker

	// closeOnce ensures finalizeCloseChannel is safe to call concurrently
	closeOnce sync.Once

	// congestionMonitor tracks local congestion state and determines D/E/G flags
	// for RouterInfo advertisement per PROP_162
	congestionMonitor *CongestionMonitor

	// inboundHandler processes inbound tunnel messages and delivers to I2CP sessions
	inboundHandler *InboundMessageHandler

	// routerInfoProv provides the local RouterInfo to the NetDB publisher
	routerInfoProv *routerInfoProvider

	// publisher publishes our RouterInfo and LeaseSets to floodfill routers
	publisher *netdb.Publisher

	// explorer actively discovers new NetDB peers via random-key XOR lookups
	explorer *netdb.Explorer

	// floodfillServer handles incoming DatabaseLookup requests when this router
	// is configured as a floodfill router
	floodfillServer *netdb.FloodfillServer

	// leaseSetPublisher handles LeaseSet publication to local NetDB and network
	leaseSetPublisher *LeaseSetPublisher

	// isReseeding tracks whether the router is currently performing a reseed operation
	isReseeding bool
	// reseedMutex protects concurrent access to isReseeding flag
	reseedMutex sync.RWMutex

	// keystoreMux protects concurrent access to RouterInfoKeystore
	keystoreMux sync.RWMutex

	// startupErr receives any error from the mainloop goroutine during
	// startup-critical initialization (NetDB, I2CP, I2PControl).  Start()
	// blocks on this channel so callers get a synchronous error report.
	startupErr chan error
}

// CreateRouter creates a router with the provided configuration
func CreateRouter(cfg *config.RouterConfig) (*Router, error) {
	if err := validateCreateRouterConfig(cfg); err != nil {
		logError("invalid router configuration", err)
		return nil, err
	}

	log.WithField("at", "CreateRouter").Debug("startup phase: creating router from config")

	r, err := FromConfig(cfg)
	if err != nil {
		logError("failed to create router from configuration", err)
		return nil, err
	}

	if err := initializeRouterComponents(r, cfg); err != nil {
		return nil, err
	}

	log.WithField("at", "CreateRouter").Debug("startup phase: router created successfully")
	return r, nil
}

// initializeRouterComponents initializes keystore, keys, RouterInfo, NetDB, and transports.
func initializeRouterComponents(r *Router, cfg *config.RouterConfig) error {
	log.WithField("at", "CreateRouter").Debug("startup phase: initializing keystore")
	if err := initializeRouterKeystore(r, cfg); err != nil {
		return err
	}

	log.WithField("at", "CreateRouter").Debug("startup phase: validating router keys")
	if err := validateRouterKeys(r); err != nil {
		return err
	}

	log.WithField("at", "CreateRouter").Debug("startup phase: constructing RouterInfo (includes signing)")
	ri, err := constructRouterInfo(r)
	if err != nil {
		return err
	}

	log.WithField("at", "CreateRouter").Debug("startup phase: initializing transports")
	return initializeNetDBAndTransports(r, ri, cfg)
}

// initializeNetDBAndTransports initializes NetDB before transports (required order).
func initializeNetDBAndTransports(r *Router, ri *router_info.RouterInfo, cfg *config.RouterConfig) error {
	// NetDB MUST be initialized before transports so that NTCP2/SSU2 can wire
	// their PeerConnNotifier into r.netdb.PeerTracker. Without this, the
	// peer-tracker only ever sees tunnel-build failures (recorded by Pool),
	// never transport-level dial attempts or successes, and every reachable
	// peer is marked stale after a single tunnel-build failure.
	if err := r.initializeNetDB(); err != nil {
		logError("failed to initialize NetDB before transports", err)
		return err
	}

	transports, err := initializeTransports(r, ri, cfg)
	if err != nil {
		return err
	}

	r.transports = transport.Mux(transports...)
	return nil
}

func validateCreateRouterConfig(cfg *config.RouterConfig) error {
	if cfg == nil {
		return oops.Errorf("router config cannot be nil")
	}
	if cfg.NetDB == nil {
		return oops.Errorf("router config NetDB cannot be nil")
	}
	if cfg.NetDB.Path == "" {
		return oops.Errorf("router config NetDB.Path cannot be empty")
	}
	return nil
}

// logError logs a startup-phase error.
func logError(reason string, err error) {
	log.WithError(err).WithFields(logger.Fields{
		"at":     "(Router) CreateRouter",
		"phase":  "startup",
		"reason": reason,
	}).Error(reason)
}

// initializeTransports creates and returns all configured transports.
func initializeTransports(r *Router, ri *router_info.RouterInfo, cfg *config.RouterConfig) ([]transport.Transport, error) {
	log.WithField("at", "initializeTransports").Debug("building NTCP2 transport")
	ntcp2Transport, err := buildNTCP2Transport(r, ri)
	if err != nil {
		return nil, err
	}
	log.WithField("at", "initializeTransports").Debug("NTCP2 transport built successfully")

	transports := []transport.Transport{ntcp2Transport}

	if cfg.Transport != nil && cfg.Transport.SSU2Enabled {
		log.WithField("at", "initializeTransports").Debug("building SSU2 transport")
		if ssu2Transport, err := buildSSU2Transport(r, ri); err != nil {
			log.WithError(err).Warn("SSU2 transport setup failed; continuing without SSU2")
		} else {
			transports = append(transports, ssu2Transport)
			// Propagate the final dual-transport RI to NTCP2 so msg3 sends
			// ri_addr_count=2 instead of the stale 1-address RI stored during
			// buildNTCP2Transport. (AUDIT FIX-1 / RC-B)
			ntcp2Transport.UpdateLocalRouterInfo(*ri)
		}
	}

	// Now that all transport addresses have been added, recompute the
	// 'R' / 'U' capability flag based on whether any of those addresses
	// carries a publishable host. If we end up upgrading caps to 'R',
	// re-publish the corrected RI to NTCP2 so msg3 reflects it.
	if err := recomputeReachabilityCaps(r, ri, ntcp2Transport); err != nil {
		log.WithError(err).Warn("failed to recompute reachability caps after transport setup")
	}

	log.WithFields(logger.Fields{"at": "initializeTransports", "count": len(transports)}).Debug("all transports initialized")
	return transports, nil
}

// recomputeReachabilityCaps inspects the addresses on ri after transport
// setup completes and reconstructs the RouterInfo with the correct
// Reachable flag if it changed. This prevents publishing 'R' caps when we
// have only caps-only / private-host transport addresses, which causes
// peers to silently reject our RI and close the NTCP2 session right after
// msg3 (manifests as 100% tunnel build expiry).
func recomputeReachabilityCaps(r *Router, ri *router_info.RouterInfo, ntcp2Transport *ntcp.NTCP2Transport) error {
	addrs := ri.RouterAddresses()
	wantReachable := hasReachableAddress(addrs)
	currentCaps := ri.RouterCapabilities()
	hasR := strings.ContainsRune(string(currentCaps), 'R')

	// No change needed.
	if wantReachable == hasR {
		return nil
	}

	rebuilt, err := r.keystore.ConstructRouterInfo(addrs, keys.RouterInfoOptions{Reachable: wantReachable})
	if err != nil {
		return oops.Wrapf(err, "rebuilding RouterInfo with Reachable=%v", wantReachable)
	}
	*ri = *rebuilt
	if ntcp2Transport != nil {
		ntcp2Transport.UpdateLocalRouterInfo(*ri)
	}
	log.WithFields(logger.Fields{
		"at":            "recomputeReachabilityCaps",
		"old_caps":      string(currentCaps),
		"new_caps":      string(ri.RouterCapabilities()),
		"want_reach":    wantReachable,
		"address_count": ri.RouterAddressCount(),
	}).Info("RouterInfo caps updated based on actual transport addresses")
	return nil
}

// initializeRouterKeystore creates and stores the router keystore
func initializeRouterKeystore(r *Router, cfg *config.RouterConfig) error {
	log.WithFields(logger.Fields{
		"at":          "(Router) initializeRouterKeystore",
		"phase":       "startup",
		"step":        3,
		"reason":      "initializing router keystore",
		"working_dir": cfg.WorkingDir,
	}).Debug("working directory is:", cfg.WorkingDir)

	keystore, err := keys.NewRouterInfoKeystore(cfg.WorkingDir, "localRouter")
	if err != nil {
		logError("failed to create RouterInfoKeystore", err)
		return err
	}
	log.WithFields(logger.Fields{
		"at":     "(Router) initializeRouterKeystore",
		"phase":  "startup",
		"step":   3,
		"reason": "keystore created successfully",
	}).Debug("routerInfoKeystore created successfully")

	if err = keystore.StoreKeys(); err != nil {
		logError("failed to store RouterInfoKeystore", err)
		return err
	}
	log.WithFields(logger.Fields{"at": "initializeRouterKeystore"}).Debug("RouterInfoKeystore stored successfully")

	r.keystore = keystore
	return nil
}

// validateRouterKeys extracts and validates the router's public key
func validateRouterKeys(r *Router) error {
	pub, _, err := r.keystore.GetKeys()
	if err != nil {
		logError("failed to get keys from RouterInfoKeystore", err)
		return err
	}

	// sha256 hash of public key
	pubHash := types.SHA256(pub.Bytes())
	b32PubHash := base32.EncodeToString(pubHash[:])
	log.WithFields(logger.Fields{"at": "validateRouterKeys"}).Debug("Router public key hash:", b32PubHash)

	return nil
}

// constructRouterInfo builds the initial router info from the keystore.
//
// We start with Reachable:false (caps='U') because at this point no
// transport addresses have been added — the addresses are appended later
// by buildNTCP2Transport / buildSSU2Transport. After all transports have
// been added, recomputeReachabilityCaps reconstructs the RouterInfo with
// Reachable:true *only* if at least one of those transport addresses
// carries a publishable host. This avoids the Java I2P / i2pd silent-drop
// (TCP close after msg3) that occurs when an RI advertises 'R' alongside
// no public endpoint or only private (RFC1918 / loopback) hosts.
func constructRouterInfo(r *Router) (*router_info.RouterInfo, error) {
	log.WithField("at", "constructRouterInfo").Debug("calling ConstructRouterInfo")
	ri, err := r.keystore.ConstructRouterInfo(nil, keys.RouterInfoOptions{Reachable: false})
	if err != nil {
		logError("failed to construct RouterInfo", err)
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":   "constructRouterInfo",
		"caps": ri.RouterCapabilities(),
	}).Debug("RouterInfo constructed successfully")
	return ri, nil
}

// FromConfig creates a minimal Router stub from config. This is a low-level
// internal function used by CreateRouter. It only initializes cfg and closeChnl.
//
// WARNING: Do not use FromConfig directly unless you intend to manually
// initialize the keystore, transport, and other subsystems afterward.
// Use CreateRouter instead, which fully initializes the router.
// Calling Start() on a router created solely via FromConfig will return
// an error because required subsystems (keystore, transport) are nil.
func FromConfig(c *config.RouterConfig) (r *Router, err error) {
	if c == nil {
		return nil, oops.Errorf("router config cannot be nil")
	}
	log.WithFields(logger.Fields{
		"at":          "(Router) FromConfig",
		"phase":       "startup",
		"step":        1,
		"reason":      "constructing router from config",
		"base_dir":    c.BaseDir,
		"working_dir": c.WorkingDir,
	}).Debug("creating router from configuration")
	r = new(Router)
	r.cfg = c
	r.closeChnl = make(chan bool)
	log.WithFields(logger.Fields{
		"at":     "(Router) FromConfig",
		"phase":  "startup",
		"reason": "router struct initialized",
	}).Debug("router created successfully from configuration")
	return r, err
}

// Wait blocks until router is fully stopped
func (r *Router) Wait() {
	log.WithFields(logger.Fields{
		"at":     "(Router) Wait",
		"phase":  "running",
		"reason": "waiting for router shutdown",
	}).Debug("waiting for router to stop")
	r.wg.Wait()
	log.WithFields(logger.Fields{
		"at":     "(Router) Wait",
		"phase":  "shutdown",
		"reason": "all router goroutines completed",
	}).Debug("router has stopped")
}

// GetTunnelManager returns the tunnel manager in a thread-safe manner.
// Returns nil if the tunnel manager has not been initialized yet.
func (r *Router) GetTunnelManager() i2np.TunnelOrchestrator {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.tunnelManager
}

// GetParticipantManager returns the participant manager for transit tunnel tracking.
// Returns nil if not initialized.
func (r *Router) GetParticipantManager() *tunnel.ParticipantManager {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.participantManager
}

// GetGarlicRouter returns the garlic router in a thread-safe manner.
// Returns nil if the garlic router has not been initialized yet.
func (r *Router) GetGarlicRouter() *GarlicMessageRouter {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.garlicRouter
}

// GetCongestionMonitor returns the congestion monitor for PROP_162 congestion cap tracking.
// Returns nil if the congestion monitor has not been initialized yet.
func (r *Router) GetCongestionMonitor() CongestionStateProvider {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.congestionMonitor
}

// GetNetDB returns the router's underlying network database instance.
func (r *Router) GetNetDB() *netdb.StdNetDB {
	return r.netdb
}

// GetConfig returns the router configuration for I2PControl.
func (r *Router) GetConfig() *config.RouterConfig {
	return r.cfg
}

// IsRunning returns whether the router is currently operational.
// Thread-safe access to running state.
func (r *Router) IsRunning() bool {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.running
}

// IsReseeding returns whether the router is currently performing a NetDB reseed operation.
// Thread-safe access to reseeding state.
func (r *Router) IsReseeding() bool {
	r.reseedMutex.RLock()
	defer r.reseedMutex.RUnlock()
	return r.isReseeding
}

// Reseed triggers an explicit NetDB reseed operation.
// This can be called via I2PControl to manually repopulate the network database.
// It runs in the current goroutine and returns any error encountered.
func (r *Router) Reseed() error {
	log.WithFields(logger.Fields{
		"at":     "(Router) Reseed",
		"reason": "explicit reseed requested",
	}).Info("Manual reseed triggered")
	return r.performReseed()
}

// GetLocalRouterIdentityHash returns the identity hash of this router as a base64-encoded string.
// This is used by I2PControl extensions for self-identification (e.g., i2p.router.hash).
func (r *Router) GetLocalRouterIdentityHash() (string, error) {
	hash, err := r.getOurRouterHash()
	if err != nil {
		return "", err
	}
	// Return as base64 (standard encoding used by Java I2P)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}
