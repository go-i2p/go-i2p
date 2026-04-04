package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/go-i2p/common/base32"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	ssu2 "github.com/go-i2p/go-i2p/lib/transport/ssu2"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

type Router struct {
	// keystore for router info
	*keys.RouterInfoKeystore
	// multi-transport manager
	*transport.TransportMuxer
	// netdb
	*netdb.StdNetDB
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

	// Session tracking for NTCP2 message routing
	activeSessions map[common.Hash]*ntcp.NTCP2Session
	// sessionMutex protects concurrent access to activeSessions map
	sessionMutex sync.RWMutex

	// I2CP server for client applications
	i2cpServer *i2cp.Server

	// tunnelManager manages tunnel building and pool maintenance
	tunnelManager *i2np.TunnelManager

	// participantManager tracks tunnels where this router acts as a transit hop
	participantManager *tunnel.Manager

	// i2pcontrolServer provides RPC monitoring interface
	i2pcontrolServer interface {
		Start() error
		Stop()
	}

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
	log.WithField("at", "CreateRouter").Debug("step 1/6: creating router from config")

	r, err := FromConfig(cfg)
	if err != nil {
		logError("failed to create router from configuration", err)
		return nil, err
	}
	log.WithField("at", "CreateRouter").Debug("step 2/6: initializing keystore")

	if err := initializeRouterKeystore(r, cfg); err != nil {
		return nil, err
	}

	log.WithField("at", "CreateRouter").Debug("step 3/6: validating router keys")
	if err := validateRouterKeys(r); err != nil {
		return nil, err
	}

	log.WithField("at", "CreateRouter").Debug("step 4/6: constructing RouterInfo (includes signing)")
	ri, err := constructRouterInfo(r)
	if err != nil {
		return nil, err
	}

	log.WithField("at", "CreateRouter").Debug("step 5/6: initializing transports")
	transports, err := initializeTransports(r, ri, cfg)
	if err != nil {
		return nil, err
	}

	r.TransportMuxer = transport.Mux(transports...)
	log.WithField("at", "CreateRouter").Debug("step 6/6: router created successfully")
	return r, nil
}

// logStartup logs a startup-phase debug message.
func logStartup(reason, baseDir, workingDir string) {
	fields := logger.Fields{
		"at":     "(Router) CreateRouter",
		"phase":  "startup",
		"reason": reason,
	}
	if baseDir != "" {
		fields["base_dir"] = baseDir
	}
	if workingDir != "" {
		fields["working_dir"] = workingDir
	}
	log.WithFields(fields).Debug(reason)
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
		}
	}

	log.WithFields(logger.Fields{"at": "initializeTransports", "count": len(transports)}).Debug("all transports initialized")
	return transports, nil
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
		log.WithError(err).WithFields(logger.Fields{
			"at":          "(Router) initializeRouterKeystore",
			"phase":       "startup",
			"reason":      "keystore creation failed",
			"working_dir": cfg.WorkingDir,
		}).Error("failed to create RouterInfoKeystore")
		return err
	}
	log.WithFields(logger.Fields{
		"at":     "(Router) initializeRouterKeystore",
		"phase":  "startup",
		"step":   3,
		"reason": "keystore created successfully",
	}).Debug("routerInfoKeystore created successfully")

	if err = keystore.StoreKeys(); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(Router) initializeRouterKeystore",
			"phase":  "startup",
			"reason": "keystore persistence failed",
		}).Error("failed to store RouterInfoKeystore")
		return err
	}
	log.WithFields(logger.Fields{"at": "initializeRouterKeystore"}).Debug("RouterInfoKeystore stored successfully")

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
	pubHash := types.SHA256(pub.Bytes())
	b32PubHash := base32.EncodeToString(pubHash[:])
	log.WithFields(logger.Fields{"at": "validateRouterKeys"}).Debug("Router public key hash:", b32PubHash)

	return nil
}

// constructRouterInfo builds the router info from the keystore
func constructRouterInfo(r *Router) (*router_info.RouterInfo, error) {
	log.WithField("at", "constructRouterInfo").Debug("calling ConstructRouterInfo")
	ri, err := r.RouterInfoKeystore.ConstructRouterInfo(nil)
	if err != nil {
		log.WithError(err).Error("Failed to construct RouterInfo")
		return nil, err
	}

	log.WithField("at", "constructRouterInfo").Debug("RouterInfo constructed successfully")
	return ri, nil
}

// resolveTransportPort returns a listen address string from transport config.
// Returns ":0" if the configured port is 0 (OS assigns a random port).
func resolveTransportPort(cfg *config.TransportDefaults, port int) string {
	p := 0
	if cfg != nil && port > 0 {
		p = port
	}
	return fmt.Sprintf(":%d", p)
}

// buildNTCP2Transport creates the NTCP2 transport, publishes its address to ri, and returns it.
func buildNTCP2Transport(r *Router, ri *router_info.RouterInfo) (*ntcp.NTCP2Transport, error) {
	log.WithField("at", "buildNTCP2Transport").Debug("resolving transport port")
	addr := resolveTransportPort(r.cfg.Transport, func() int {
		if r.cfg.Transport != nil {
			return r.cfg.Transport.NTCP2Port
		}
		return 0
	}())
	log.WithFields(logger.Fields{"at": "buildNTCP2Transport", "addr": addr}).Debug("creating NTCP2 config")
	ntcp2Config, err := ntcp.NewConfig(addr)
	if err != nil {
		log.WithError(err).Error("Failed to create NTCP2 config")
		return nil, err
	}
	ntcp2Config.WorkingDir = r.cfg.WorkingDir

	log.WithField("at", "buildNTCP2Transport").Debug("creating NTCP2 transport instance")
	ntcp2Transport, err := ntcp.NewNTCP2Transport(*ri, ntcp2Config, r.RouterInfoKeystore)
	if err != nil {
		log.WithError(err).Error("Failed to create NTCP2 transport")
		return nil, err
	}
	log.WithFields(logger.Fields{"at": "buildNTCP2Transport"}).Debug("NTCP2 transport created successfully")

	ntcpaddr := ntcp2Transport.Addr()
	if err := validateAndAddTransportAddress(ri, ntcpaddr, "NTCP2", func() (*router_address.RouterAddress, error) {
		return ntcp.ConvertToRouterAddress(ntcp2Transport)
	}); err != nil {
		return nil, err
	}

	return ntcp2Transport, nil
}

// buildSSU2Transport creates the SSU2 transport, publishes its address to ri, and returns it.
func buildSSU2Transport(r *Router, ri *router_info.RouterInfo) (*ssu2.SSU2Transport, error) {
	addr := resolveTransportPort(r.cfg.Transport, func() int {
		if r.cfg.Transport != nil {
			return r.cfg.Transport.SSU2Port
		}
		return 0
	}())

	ssu2Config, err := ssu2.NewConfig(addr)
	if err != nil {
		log.WithError(err).Error("Failed to create SSU2 config")
		return nil, err
	}
	ssu2Config.WorkingDir = r.cfg.WorkingDir

	ssu2Transport, err := ssu2.NewSSU2Transport(*ri, ssu2Config, r.RouterInfoKeystore)
	if err != nil {
		log.WithError(err).Error("Failed to create SSU2 transport")
		return nil, err
	}

	// Wire router lookup so SSU2 can connect via introducers.
	ssu2Config.RouterLookupFunc = func(hash common.Hash) (router_info.RouterInfo, error) {
		ch := r.StdNetDB.GetRouterInfo(hash)
		select {
		case ri, ok := <-ch:
			if !ok {
				return router_info.RouterInfo{}, fmt.Errorf("router %x not found in netdb", hash[:4])
			}
			return ri, nil
		}
	}

	log.WithFields(logger.Fields{"at": "buildSSU2Transport"}).Debug("SSU2 transport created successfully")

	ssu2addr := ssu2Transport.Addr()
	if err := validateAndAddTransportAddress(ri, ssu2addr, "SSU2", func() (*router_address.RouterAddress, error) {
		return ssu2.ConvertToRouterAddress(ssu2Transport)
	}); err != nil {
		return nil, err
	}

	return ssu2Transport, nil
}

// validateAndAddTransportAddress validates that addr is non-nil, logs it, and calls addTransportAddress.
// This reduces code duplication between buildNTCP2Transport and buildSSU2Transport.
func validateAndAddTransportAddress(ri *router_info.RouterInfo, addr net.Addr, proto string, converter func() (*router_address.RouterAddress, error)) error {
	if addr == nil {
		log.WithFields(logger.Fields{"at": "validateAndAddTransportAddress"}).Error("Failed to get " + proto + " address")
		return errors.New("failed to get " + proto + " address")
	}
	log.WithFields(logger.Fields{"at": "validateAndAddTransportAddress"}).Debug(proto+" address:", addr)
	return addTransportAddress(ri, addr, proto, converter)
}

// addTransportAddress converts a transport's address to a RouterAddress via converter
// and appends it to ri. proto is used in log messages only.
func addTransportAddress(ri *router_info.RouterInfo, addr net.Addr, proto string, converter func() (*router_address.RouterAddress, error)) error {
	routerAddress, err := converter()
	if err != nil {
		log.WithError(err).Errorf("Failed to convert %s address to RouterAddress", proto)
		return fmt.Errorf("failed to convert %s address: %w", proto, err)
	}
	ri.AddAddress(routerAddress)
	log.WithFields(logger.Fields{
		"host": addr.String(),
		"cost": routerAddress.Cost(),
	}).Infof("%s address added to RouterInfo", proto)
	return nil
}

// getTotalBandwidth returns the total bytes sent and received from all transports.
// This method is used by the bandwidth tracker to sample bandwidth usage.
func (r *Router) getTotalBandwidth() (sent, received uint64) {
	// Capture TransportMuxer locally to avoid TOCTOU race:
	// the field could be set to nil by concurrent shutdown between
	// the nil check and the method call.
	muxer := r.TransportMuxer
	if muxer == nil {
		return 0, 0
	}

	// Get all transports from the muxer
	for _, t := range muxer.GetTransports() {
		switch tr := t.(type) {
		case *ntcp.NTCP2Transport:
			s, rcv := tr.GetTotalBandwidth()
			sent += s
			received += rcv
		case *ssu2.SSU2Transport:
			s, rcv := tr.GetTotalBandwidth()
			sent += s
			received += rcv
		}
	}
	return sent, received
}

// GetBandwidthRates returns the current 15-second inbound and outbound bandwidth rates.
// Returns rates in bytes per second.
func (r *Router) GetBandwidthRates() (inbound, outbound uint64) {
	if r.bandwidthTracker == nil {
		return 0, 0
	}
	return r.bandwidthTracker.GetRates()
}

// GetActiveSessionCount returns the number of active transport sessions.
// Thread-safe access to the activeSessions map.
func (r *Router) GetActiveSessionCount() int {
	r.sessionMutex.RLock()
	defer r.sessionMutex.RUnlock()
	return len(r.activeSessions)
}

// GetTransportAddr returns the listening address of the first available transport.
// This is used by I2PControl to expose NTCP2 port and address information.
// Returns nil if no transports are available.
func (r *Router) GetTransportAddr() interface{} {
	// Capture locally to avoid TOCTOU race with concurrent shutdown.
	muxer := r.TransportMuxer
	if muxer == nil {
		return nil
	}

	transports := muxer.GetTransports()
	if len(transports) == 0 {
		return nil
	}

	// Return the address of the first transport (typically NTCP2)
	return transports[0].Addr()
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
		return nil, fmt.Errorf("router config cannot be nil")
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
func (r *Router) GetTunnelManager() *i2np.TunnelManager {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.tunnelManager
}

// GetParticipantManager returns the participant manager for transit tunnel tracking.
// Returns nil if not initialized.
func (r *Router) GetParticipantManager() *tunnel.Manager {
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

func (r *Router) GetNetDB() *netdb.StdNetDB {
	return r.StdNetDB
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

// hasNTCP2Address checks if RouterInfo contains at least one NTCP2 address
func hasNTCP2Address(routerInfo router_info.RouterInfo) bool {
	for _, addr := range routerInfo.RouterAddresses() {
		style := addr.TransportStyle()
		if styleStr, err := style.Data(); err == nil && strings.EqualFold(styleStr, "NTCP2") {
			return true
		}
	}
	return false
}

// routerBandwidthProvider adapts the router config to the I2CP bandwidth
// limits interface so the I2CP server returns the real configured limit
// instead of a hardcoded value.
type routerBandwidthProvider struct {
	cfg *config.RouterConfig
}

// GetBandwidthLimits returns the router's configured MaxBandwidth for both
// inbound and outbound directions. If MaxBandwidth is 0 (unlimited) or
// exceeds uint32 range, it clamps to math.MaxUint32.
func (bp *routerBandwidthProvider) GetBandwidthLimits() (inbound, outbound uint32) {
	bw := bp.cfg.MaxBandwidth
	if bw == 0 || bw > uint64(^uint32(0)) {
		return ^uint32(0), ^uint32(0) // unlimited
	}
	limit := uint32(bw)
	return limit, limit
}
