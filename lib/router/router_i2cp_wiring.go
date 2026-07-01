package router

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/naming"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"

	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// ensureNetDBReady validates NetDB state and performs reseed if needed.
// Returns an error if the router's StdNetDB is nil (e.g. during shutdown).

// startI2CPServer initializes and starts the I2CP server
func (r *Router) startI2CPServer() error {
	server, err := r.createI2CPServer()
	if err != nil {
		return err
	}

	r.configureI2CPServerInfrastructure(server)

	if err := server.Start(); err != nil {
		return oops.Wrapf(err, "failed to start I2CP server")
	}

	r.i2cpServer = server

	log.WithFields(logger.Fields{
		"address":      r.cfg.I2CP.Address,
		"network":      r.cfg.I2CP.Network,
		"max_sessions": r.cfg.I2CP.MaxSessions,
	}).Info("I2CP server started")

	return nil
}

// createI2CPServer creates a new I2CP server with the router's configuration.
func (r *Router) createI2CPServer() (*i2cp.Server, error) {
	serverConfig := &i2cp.ServerConfig{
		ListenAddr:                 r.cfg.I2CP.Address,
		Network:                    r.cfg.I2CP.Network,
		MaxSessions:                r.cfg.I2CP.MaxSessions,
		ReadTimeout:                r.cfg.I2CP.ReadTimeout,
		WriteTimeout:               r.cfg.I2CP.WriteTimeout,
		SessionTimeout:             r.cfg.I2CP.SessionTimeout,
		AllowInsecureCleartextAuth: r.cfg.I2CP.AllowInsecureCleartextAuth,
		LeaseSetPublisher:          nil, // C1 FIX: Will be set later via SetLeaseSetPublisher after publisher is started
	}

	server, err := i2cp.NewServer(serverConfig)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create I2CP server")
	}
	return server, nil
}

// configureI2CPServerInfrastructure sets up NetDB, auth, bandwidth, tunnels, and peer selection.
func (r *Router) configureI2CPServerInfrastructure(server *i2cp.Server) {
	server.SetNetDB(r.netdb)
	r.configureI2CPRouterHash(server)
	r.configureI2CPAuth(server)
	server.SetBandwidthProvider(&routerBandwidthProvider{cfg: r.cfg})
	r.configureI2CPTunnelBuilder(server)
	r.configureI2CPPeerSelector(server)
	r.configureI2CPHostnameResolver(server)
	r.configureI2CPDestinationResolver(server)
	r.wireI2CPMessageRouter(server)
}

// configureI2CPRouterHash sets the router hash for I2CP session tunnel pools.
func (r *Router) configureI2CPRouterHash(server *i2cp.Server) {
	routerHash, err := r.getOurRouterHash()
	if err != nil {
		log.WithError(err).Warn("I2CP server: unable to configure router hash for session tunnel pools")
		return
	}
	server.SetRouterHash(routerHash)
}

// retryI2CPRouterHashWiring retries I2CP router-hash propagation for session
// tunnel pools in case early startup ordering caused initial hash derivation to fail.
func (r *Router) retryI2CPRouterHashWiring() {
	if r.i2cpServer == nil {
		return
	}
	routerHash, err := r.getOurRouterHash()
	if err != nil {
		log.WithError(err).WithField("at", "retryI2CPRouterHashWiring").Debug("router hash still unavailable for I2CP session pools")
		return
	}
	r.i2cpServer.SetRouterHash(routerHash)
}

// configureI2CPAuth sets up password authentication if credentials are provided.
func (r *Router) configureI2CPAuth(server *i2cp.Server) {
	if r.cfg.I2CP.Username == "" || r.cfg.I2CP.Password == "" {
		return
	}

	auth, err := i2cp.NewPasswordAuthenticator(r.cfg.I2CP.Username, r.cfg.I2CP.Password)
	if err != nil {
		return
	}

	server.SetAuthenticator(auth)
	log.WithFields(logger.Fields{"at": "configureI2CPServerInfrastructure"}).Info("I2CP server: authentication enabled")
}

// configureI2CPTunnelBuilder sets up the tunnel builder if available.
func (r *Router) configureI2CPTunnelBuilder(server *i2cp.Server) {
	if r.tunnelManager == nil {
		log.WithFields(logger.Fields{"at": "configureI2CPServerInfrastructure"}).Debug("I2CP server: tunnel manager not available for session pools")
		return
	}

	server.SetTunnelBuilder(r.tunnelManager)
	log.WithFields(logger.Fields{"at": "configureI2CPServerInfrastructure"}).Debug("I2CP server: tunnel builder configured")
}

// configureI2CPPeerSelector creates and sets the peer selector for I2CP sessions.
func (r *Router) configureI2CPPeerSelector(server *i2cp.Server) {
	peerSelector, err := tunnel.NewDefaultPeerSelector(r.netdb)
	if err != nil {
		log.WithError(err).Warn("Failed to create peer selector for I2CP sessions")
		return
	}

	server.SetPeerSelector(peerSelector)
	log.WithFields(logger.Fields{"at": "configureI2CPServerInfrastructure"}).Debug("I2CP server: peer selector configured")
}

// configureI2CPHostnameResolver creates and sets the hostname resolver for I2CP.
func (r *Router) configureI2CPHostnameResolver(server *i2cp.Server) {
	hostResolver, err := naming.NewHostsTxtResolver()
	if err != nil {
		log.WithError(err).Warn("Failed to create hostname resolver for I2CP")
		return
	}

	server.SetHostnameResolver(hostResolver)
	log.WithFields(logger.Fields{"at": "configureI2CPServerInfrastructure"}).Debug("I2CP server: hostname resolver configured")
}

// configureI2CPDestinationResolver creates and sets the destination resolver for I2CP.
func (r *Router) configureI2CPDestinationResolver(server *i2cp.Server) {
	destResolver := netdb.NewDestinationResolver(r.netdb)
	server.SetDestinationResolver(destResolver)
	log.WithFields(logger.Fields{"at": "configureI2CPServerInfrastructure"}).Debug("I2CP server: destination resolver configured")
}

// wireI2CPMessageRouter creates and injects a MessageRouter into the I2CP server.
// The MessageRouter handles outbound message encryption via garlic sessions and
// sends encrypted messages through the transport layer to tunnel gateways.
func (r *Router) wireI2CPMessageRouter(server *i2cp.Server) {
	privKeyBytes := r.keystore.GetEncryptionPrivateKey().Bytes()
	var privKey [32]byte
	copy(privKey[:], privKeyBytes)

	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	if err != nil {
		log.WithError(err).Error("I2CP server: failed to create garlic session manager — outbound routing disabled")
		return
	}

	transportSend := func(peerHash common.Hash, msg i2np.Message) error {
		session, sErr := r.GetSessionByHash(peerHash)
		if sErr != nil {
			return oops.Wrapf(sErr, "no session for peer %x", peerHash[:8])
		}
		return session.QueueSendI2NP(msg)
	}

	msgRouter := i2cp.NewMessageRouter(garlicMgr, transportSend)
	server.SetMessageRouter(msgRouter)
	log.WithFields(logger.Fields{"at": "wireI2CPMessageRouter"}).Debug("I2CP server: message router configured for outbound routing")
}
