package router

import (
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"
)

// logSubsystemStop logs a subsystem shutdown event with standard fields.
// This reduces duplication across the various stopXxx methods.

// initializeMessageRouter sets up message routing with NetDB integration
func (r *Router) initializeMessageRouter() {
	messageConfig := i2np.I2NPMessageDispatcherConfig{
		MaxRetries:     3,
		DefaultTimeout: 30 * time.Second,
		EnableLogging:  true,
	}
	r.messageRouter = i2np.NewI2NPMessageDispatcher(messageConfig)
	r.messageRouter.SetNetDB(r.netdb)
	r.messageRouter.SetPeerSelector(r.netdb)
	r.messageRouter.SetSessionProvider(r)

	r.initializeTunnelManager()
	r.wireDispatcherTunnelManager()
	r.wireParticipantManager()
	r.initializeGarlicRouter()
	r.wireGarlicSessionManager()
	r.wireTunnelDataHandler()
	r.wireTunnelGatewayHandler()
	r.wireBuildRecordIdentity()
	r.wireI2CPTunnelBuilder()

	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("Message router initialized with NetDB, peer selection, session provider, tunnel data handler, garlic sessions, and garlic forwarding")
}

// wireDispatcherTunnelManager unifies the dispatcher's tunnel manager with the router's.
func (r *Router) wireDispatcherTunnelManager() {
	r.messageRouter.SetTunnelManager(r.tunnelManager)
	r.messageRouter.GetProcessor().SetBuildReplyProcessor(r.tunnelManager)
	// C-1 fix: wire the inbound handler into the tunnel manager so that newly-active
	// inbound tunnels are registered as control-plane endpoints immediately on success.
	if r.inboundHandler != nil {
		r.tunnelManager.SetInboundHandler(r.inboundHandler)
	}
	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("Dispatcher tunnel manager unified with router tunnel manager")
}

// wireParticipantManager initializes and wires the participant manager for transit tunnels.
func (r *Router) wireParticipantManager() {
	r.participantManager = tunnel.NewManager()
	r.messageRouter.GetProcessor().SetParticipantManager(r.participantManager)
	r.messageRouter.GetProcessor().SetBuildReplyForwarder(&transportBuildReplyForwarder{sessionProvider: r})
	// Apply the no-transit policy: hidden mode or AcceptTunnels=false both
	// require unconditional rejection of incoming tunnel build requests.
	if r.cfg != nil && (r.cfg.Hidden || !r.cfg.AcceptTunnels) {
		r.participantManager.SetRefuseAllTransit(true)
	}
	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("Participant manager and build reply forwarder wired into message processor")
}

// wireTunnelDataHandler wires the inbound message handler as the TunnelData handler
// and wires the participant manager and session provider for transit tunnel forwarding.
func (r *Router) wireTunnelDataHandler() {
	if r.inboundHandler != nil {
		r.messageRouter.GetProcessor().SetTunnelDataHandler(r.inboundHandler)
		// Wire the participant manager for transit tunnel handling
		if r.participantManager != nil {
			r.inboundHandler.SetParticipantManager(r.participantManager)
		}
		// Wire the session provider for forwarding transit tunnel messages
		r.inboundHandler.SetSessionProvider(r)
		// C-1 fix: give inboundHandler access to the MessageProcessor so that
		// decrypted messages from exploratory tunnels are dispatched as I2NP.
		r.inboundHandler.SetProcessor(r.messageRouter.GetProcessor())
		log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("InboundMessageHandler wired as TunnelData handler with participant manager and session provider for transit forwarding")
	}
}

// wireTunnelGatewayHandler wires a TunnelGateway handler that re-parses the
// inner I2NP message from the gateway payload and dispatches it through the
// message processor. This is needed so that STBM build replies (type 26)
// wrapped inside a TunnelGateway (type 19) are properly processed.
func (r *Router) wireTunnelGatewayHandler() {
	r.messageRouter.GetProcessor().SetTunnelGatewayHandler(&tunnelGatewayDispatcher{
		processor: r.messageRouter.GetProcessor(),
	})
	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("TunnelGateway dispatcher wired into message processor")
}

// tunnelGatewayDispatcher implements i2np.TunnelGatewayHandler by parsing the
// inner I2NP message from a TunnelGateway payload and re-dispatching it.
type tunnelGatewayDispatcher struct {
	processor *i2np.MessageProcessor
}

// HandleGateway parses and dispatches an inner I2NP message carried in a
// TunnelGateway payload.
func (d *tunnelGatewayDispatcher) HandleGateway(tunnelID tunnel.TunnelID, payload []byte) error {
	// BUG-4 fix: use the short-format minimum (9 bytes) as the floor so that
	// valid 9–15 byte short I2NP messages are not rejected before the fallback
	// path is attempted. The previous guard of < 16 was too strict.
	if len(payload) < i2np.ShortI2NPHeaderSize {
		return oops.Errorf("TunnelGateway payload too short: %d bytes", len(payload))
	}
	inner := &i2np.BaseI2NPMessage{}
	if err := inner.UnmarshalBinary(payload); err != nil {
		// Fall back to short I2NP format (9-byte header) in case the payload
		// uses NTCP2 short format.
		inner2 := &i2np.BaseI2NPMessage{}
		if err2 := inner2.UnmarshalShortI2NP(payload); err2 != nil {
			return oops.Wrapf(err, "failed to parse inner I2NP message from TunnelGateway payload (standard: %v, short: %v)", err, err2)
		}
		inner = inner2
	}
	i2np.RecordExploratoryReplyStage(i2np.ExploratoryReplyStageTunnelGatewayParsed)
	log.WithFields(logger.Fields{
		"outer_tunnel_id": tunnelID,
		"inner_type":      inner.Type(),
		"inner_msg_id":    inner.MessageID(),
		"payload_size":    len(payload),
	}).Debug("TunnelGateway: dispatching inner I2NP message")
	return d.processor.ProcessMessage(inner)
}

// wireBuildRecordIdentity wires router identity and crypto keys for build record decryption.
func (r *Router) wireBuildRecordIdentity() {
	routerHash, err := r.getOurRouterHash()
	if err != nil {
		log.WithError(err).Error("Failed to get router hash for build record identity — transit tunnel building will be degraded")
		return
	}
	privKeyBytes := r.keystore.GetEncryptionPrivateKey().Bytes()
	buildCrypto := i2np.NewBuildRecordCrypto()
	r.messageRouter.GetProcessor().SetOurRouterHash(routerHash)
	r.messageRouter.GetProcessor().SetBuildRequestDecryptor(buildCrypto)
	r.messageRouter.GetProcessor().SetOurPrivateKey(privKeyBytes)
	// Propagate our router hash to the tunnel manager so pools can set
	// ReplyGateway correctly. Without this, the last hop in every build
	// sends the reply to an all-zeros peer and builds always expire.
	if r.tunnelManager != nil {
		r.tunnelManager.SetOurRouterHash(routerHash)
	}
	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("MessageProcessor identity, decryptor, and private key wired for build record decryption")
}

// wireI2CPTunnelBuilder wires the tunnel manager into the I2CP server.
func (r *Router) wireI2CPTunnelBuilder() {
	if r.i2cpServer != nil && r.tunnelManager != nil {
		r.i2cpServer.SetTunnelBuilder(r.tunnelManager)
		log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("I2CP server: tunnel builder wired after tunnel manager initialization")
	}
}

// configureRouterHashOnPools sets the router's hash on both tunnel pools.
// This must be done before starting maintenance to ensure build requests
// have valid identity information.
func (r *Router) configureRouterHashOnPools(inboundPool, outboundPool *tunnel.Pool) error {
	routerHash, err := r.getOurRouterHash()
	if err != nil {
		return err
	}
	
	// CRITICAL: Verify hash is valid before setting
	if len(routerHash) == 0 {
		return oops.Errorf("router hash is empty after computation")
	}
	
	// Log the hash being set (first 16 chars in hex for debugging)
	hashHex := routerHash.String()
	if len(hashHex) > 16 {
		hashHex = hashHex[:16]
	}
	
	if outboundPool != nil {
		outboundPool.SetRouterHash(routerHash)
		log.WithFields(logger.Fields{
			"at": "configureRouterHashOnPools",
			"pool": "outbound",
			"router_hash": hashHex,
		}).Info("Router hash set on outbound pool")
	}
	if inboundPool != nil {
		inboundPool.SetRouterHash(routerHash)
		log.WithFields(logger.Fields{
			"at": "configureRouterHashOnPools",
			"pool": "inbound",
			"router_hash": hashHex,
		}).Info("Router hash set on inbound pool")
	}
	return nil
}

// configureInboundPoolPolicy configures hop count and auto-fallback for the inbound pool.
// Returns true if zero-hop mode is enabled.
func (r *Router) configureInboundPoolPolicy(inboundPool *tunnel.Pool) bool {
	if inboundPool == nil {
		return false
	}

	zeroHopInbound := r.cfg != nil && (r.cfg.Hidden || r.cfg.AlwaysZeroHopInbound)
	if zeroHopInbound {
		if err := inboundPool.SetHopCount(0); err != nil {
			log.WithError(err).Error("Failed to enable zero-hop inbound tunnels")
		} else {
			log.WithFields(logger.Fields{
				"at":                      "configureInboundPoolPolicy",
				"hidden":                  r.cfg.Hidden,
				"always_zero_hop_inbound": r.cfg.AlwaysZeroHopInbound,
			}).Info("Inbound exploratory pool configured for zero-hop tunnels")
		}
	} else {
		// Wire auto-fallback: after autoFallbackThreshold consecutive build
		// timeouts, automatically switch to 0-hop inbound when no public
		// address is confirmed.
		inboundPool.SetAutoFallbackCheck(func() bool {
			return r.collectBestExternalAddr() == ""
		})
	}
	return zeroHopInbound
}

// configureOutboundPoolPolicy configures hop count and auto-fallback for the outbound pool.
// Returns true if one-hop mode is enabled.
func (r *Router) configureOutboundPoolPolicy(outboundPool *tunnel.Pool) bool {
	if outboundPool == nil {
		return false
	}

	oneHopOutbound := r.cfg != nil && (r.cfg.Hidden || r.cfg.AlwaysOneHopOutbound)
	if oneHopOutbound {
		if err := outboundPool.SetHopCount(1); err != nil {
			log.WithError(err).Error("Failed to enable one-hop outbound tunnels")
		} else {
			log.WithFields(logger.Fields{
				"at":                      "configureOutboundPoolPolicy",
				"hidden":                  r.cfg.Hidden,
				"always_one_hop_outbound": r.cfg.AlwaysOneHopOutbound,
			}).Info("Outbound exploratory pool configured for one-hop tunnels")
		}
	} else {
		// Wire auto-fallback: after autoFallbackThreshold consecutive outbound
		// build timeouts with no public address, switch to 1-hop outbound.
		outboundPool.SetAutoFallbackCheck(func() bool {
			return r.collectBestExternalAddr() == ""
		})
	}
	return oneHopOutbound
}

// wireReplyTunnelProviders configures reply tunnel providers for both pools.
// This enables TUNNEL delivery mode instead of ROUTER delivery mode,
// which works better behind NAT.
func (r *Router) wireReplyTunnelProviders(inboundPool, outboundPool *tunnel.Pool) {
	if inboundPool == nil {
		return
	}

	makeProvider := func(pool *tunnel.Pool) func() (tunnel.TunnelID, bool) {
		return func() (tunnel.TunnelID, bool) {
			active := pool.GetActiveTunnels()
			if len(active) == 0 {
				return 0, false
			}
			// Prefer the oldest active tunnel for stability.
			return active[0].ID, true
		}
	}

	inboundPool.SetReplyTunnelProvider(makeProvider(inboundPool))
	if outboundPool != nil {
		outboundPool.SetReplyTunnelProvider(makeProvider(inboundPool))
	}
}

// startPoolMaintenance starts maintenance goroutines for both tunnel pools.
func (r *Router) startPoolMaintenance(tm *i2np.TunnelManager, inboundPool, outboundPool *tunnel.Pool) {
	for _, pool := range []*tunnel.Pool{inboundPool, outboundPool} {
		if pool == nil {
			continue
		}
		pool.SetTunnelBuilder(tm)
		pool.SetPeerTracker(r.netdb.PeerTracker)
		if err := pool.StartMaintenance(); err != nil {
			log.WithError(err).Error("Failed to start tunnel pool maintenance")
		}
	}
}

// launchInboundReadinessWatcher launches a goroutine that monitors inbound pool
// readiness and closes the gate channel when ready or on timeout.
func (r *Router) launchInboundReadinessWatcher(inboundPool, outboundPool *tunnel.Pool, inboundReady chan struct{}) {
	go func() {
		deadline := time.NewTimer(2 * tunnel.BuildTimeout)
		defer deadline.Stop()
		poll := time.NewTicker(500 * time.Millisecond)
		defer poll.Stop()

		r.runInboundReadinessLoop(inboundPool, outboundPool, inboundReady, deadline, poll)
	}()
}

// runInboundReadinessLoop polls for inbound pool readiness with timeout handling.
func (r *Router) runInboundReadinessLoop(inboundPool, outboundPool *tunnel.Pool, inboundReady chan struct{}, deadline *time.Timer, poll *time.Ticker) {
	for {
		select {
		case <-r.ctx.Done():
			close(inboundReady)
			return
		case <-deadline.C:
			r.handleInboundReadinessTimeout(inboundPool, outboundPool, inboundReady)
			return
		case <-poll.C:
			if r.checkInboundPoolReady(inboundPool, inboundReady) {
				return
			}
		}
	}
}

// checkInboundPoolReady checks if the inbound pool has active tunnels.
func (r *Router) checkInboundPoolReady(inboundPool *tunnel.Pool, inboundReady chan struct{}) bool {
	if inboundPool != nil && len(inboundPool.GetActiveTunnels()) > 0 {
		log.WithFields(logger.Fields{
			"at": "launchInboundReadinessWatcher",
		}).Debug("inbound pool ready; releasing outbound pool startup gate")
		close(inboundReady)
		return true
	}
	return false
}

// handleInboundReadinessTimeout handles the case when inbound pool doesn't
// become ready within the timeout period.
func (r *Router) handleInboundReadinessTimeout(inboundPool, outboundPool *tunnel.Pool, inboundReady chan struct{}) {
	log.WithFields(logger.Fields{
		"at":      "handleInboundReadinessTimeout",
		"timeout": 2 * tunnel.BuildTimeout,
	}).Warn("inbound pool readiness timeout; enforcing fallback before releasing outbound gate")

	// Force outbound to 1-hop first
	if outboundPool != nil {
		if err := outboundPool.SetHopCount(1); err != nil {
			log.WithFields(logger.Fields{
				"at":    "handleInboundReadinessTimeout",
				"error": err.Error(),
			}).Warn("failed to force outbound exploratory pool to one-hop")
		}
	}

	// Force inbound to 0-hop
	if inboundPool != nil {
		if err := inboundPool.SetHopCount(0); err != nil {
			log.WithFields(logger.Fields{
				"at":    "handleInboundReadinessTimeout",
				"error": err.Error(),
			}).Warn("failed to force inbound exploratory pool to zero-hop")
		}
		inboundPool.RunMaintenanceNow()
	}

	// Wait for 0-hop inbound to appear
	r.waitForFallbackInbound(inboundPool, inboundReady)
}

// waitForFallbackInbound waits up to 5s for 0-hop inbound tunnel after fallback.
func (r *Router) waitForFallbackInbound(inboundPool *tunnel.Pool, inboundReady chan struct{}) {
	fallbackPoll := time.NewTicker(300 * time.Millisecond)
	fallbackDeadline := time.NewTimer(5 * time.Second)
	defer fallbackPoll.Stop()
	defer fallbackDeadline.Stop()

	r.runFallbackInboundLoop(inboundPool, inboundReady, fallbackDeadline, fallbackPoll)
}

// runFallbackInboundLoop polls for fallback inbound pool readiness with timeout.
func (r *Router) runFallbackInboundLoop(inboundPool *tunnel.Pool, inboundReady chan struct{}, deadline *time.Timer, poll *time.Ticker) {
	for {
		select {
		case <-r.ctx.Done():
			close(inboundReady)
			return
		case <-deadline.C:
			r.handleFallbackTimeout(inboundReady)
			return
		case <-poll.C:
			if r.checkFallbackInboundReady(inboundPool, inboundReady) {
				return
			}
		}
	}
}

// handleFallbackTimeout handles the secondary fallback readiness timeout.
func (r *Router) handleFallbackTimeout(inboundReady chan struct{}) {
	log.WithFields(logger.Fields{
		"at": "waitForFallbackInbound",
	}).Warn("secondary fallback readiness timeout; releasing outbound gate")
	close(inboundReady)
}

// checkFallbackInboundReady checks if the fallback inbound pool has active tunnels.
func (r *Router) checkFallbackInboundReady(inboundPool *tunnel.Pool, inboundReady chan struct{}) bool {
	if inboundPool != nil && len(inboundPool.GetActiveTunnels()) > 0 {
		log.WithFields(logger.Fields{
			"at": "waitForFallbackInbound",
		}).Debug("0-hop inbound ready after fallback; releasing outbound gate")
		close(inboundReady)
		return true
	}
	return false
}

// launchProactiveFallbackChecks starts goroutines that trigger auto-fallback
// after one build timeout if no tunnels are established.
func (r *Router) launchProactiveFallbackChecks(inboundPool, outboundPool *tunnel.Pool, zeroHopInbound, oneHopOutbound bool) {
	if !zeroHopInbound && inboundPool != nil {
		r.launchInboundFallbackCheck(inboundPool)
	}

	if !oneHopOutbound && outboundPool != nil {
		r.launchOutboundFallbackCheck(outboundPool)
	}
}

// launchInboundFallbackCheck starts a goroutine to trigger inbound fallback after timeout.
//
// After a full build-timeout window (plus a small grace) has elapsed with zero
// active tunnels, the current hop configuration has demonstrably failed to build
// any tunnel. That is stronger, direct evidence of unreachability than the
// address-form heuristic used by TriggerAutoFallbackCheck, so we force the
// fallback unconditionally and immediately run a maintenance cycle to build the
// reduced-hop (zero-hop inbound) tunnel without waiting for the next ticker.
func (r *Router) launchInboundFallbackCheck(pool *tunnel.Pool) {
	go func() {
		select {
		case <-r.ctx.Done():
			return
		case <-time.After(tunnel.BuildTimeout + 5*time.Second):
			if len(pool.GetActiveTunnels()) == 0 {
				pool.ForceAutoFallback()
				pool.RunMaintenanceNow()
			}
		}
	}()
}

// launchOutboundFallbackCheck starts a goroutine to trigger outbound fallback after timeout.
//
// See launchInboundFallbackCheck: zero active tunnels after the build-timeout
// window is direct evidence the current outbound hop configuration cannot
// complete, so the fallback to one-hop is forced regardless of the address-form
// reachability heuristic.
func (r *Router) launchOutboundFallbackCheck(pool *tunnel.Pool) {
	go func() {
		select {
		case <-r.ctx.Done():
			return
		case <-time.After(tunnel.BuildTimeout + 5*time.Second):
			if len(pool.GetActiveTunnels()) == 0 {
				pool.ForceAutoFallback()
				pool.RunMaintenanceNow()
			}
		}
	}()
}

// initializeTunnelManager creates and configures the tunnel manager for building and maintaining tunnels.
// The tunnel manager coordinates tunnel building, maintains tunnel pools, and handles tunnel lifecycle.
func (r *Router) initializeTunnelManager() {
	// Create tunnel manager with NetDB as peer selector
	tm := i2np.NewTunnelManager(r.netdb)

	// Set router as session provider for sending tunnel build messages
	tm.SetSessionProvider(r)

	// Assign to router field with lock protection
	r.runMux.Lock()
	r.tunnelManager = tm
	r.runMux.Unlock()

	// Get tunnel pools
	outboundPool := tm.GetOutboundPool()
	inboundPool := tm.GetInboundPool()

	// Set router hash on pools before starting maintenance
	if err := r.configureRouterHashOnPools(inboundPool, outboundPool); err != nil {
		log.WithError(err).Error("Failed to get router hash for tunnel pools; skipping maintenance startup until identity is available")
		return
	}

	// Configure pool policies (hop count, auto-fallback) before starting maintenance
	zeroHopInbound := r.configureInboundPoolPolicy(inboundPool)
	oneHopOutbound := r.configureOutboundPoolPolicy(outboundPool)

	// Gate outbound pool's first build on inbound readiness
	inboundReady := make(chan struct{})
	if outboundPool != nil {
		outboundPool.SetStartupGate(inboundReady)
	}

	// Wire reply tunnel providers for both pools
	r.wireReplyTunnelProviders(inboundPool, outboundPool)

	// Start maintenance on both pools
	r.startPoolMaintenance(tm, inboundPool, outboundPool)

	// Launch watcher for inbound pool readiness
	r.launchInboundReadinessWatcher(inboundPool, outboundPool, inboundReady)

	// Launch proactive fallback checks after one build timeout
	r.launchProactiveFallbackChecks(inboundPool, outboundPool, zeroHopInbound, oneHopOutbound)

	log.WithFields(logger.Fields{
		"at":            "initializeTunnelManager",
		"inbound_pool":  inboundPool != nil,
		"outbound_pool": outboundPool != nil,
		"peer_tracker":  r.netdb.PeerTracker != nil,
	}).Debug("Tunnel pools configured and maintenance started")

	log.WithFields(logger.Fields{
		"peer_selector": "netdb",
		"pools_created": true,
	}).Debug("Tunnel manager initialized with peer selection")
}

// initializeGarlicRouter sets up garlic message forwarding for non-LOCAL delivery types.
// This enables DESTINATION (0x01), ROUTER (0x02), and TUNNEL (0x03) garlic clove deliveries.
func (r *Router) initializeGarlicRouter() {
	// Get our router identity hash for reflexive delivery detection
	routerHash, err := r.getOurRouterHash()
	if err != nil {
		log.WithError(err).Error("Failed to get our router hash - garlic routing may not properly detect self-addressed messages")
		// Continue with zero hash; the router can still function but reflexive routing won't work
	}

	// Wrap StdNetDB with adapter to match GarlicNetDB interface
	garlicNetDB := newNetDBAdapter(r.netdb)

	// Get tunnel pool from tunnel manager if available, otherwise nil
	var tunnelPool *tunnel.Pool
	if r.tunnelManager != nil {
		tunnelPool = r.tunnelManager.GetOutboundPool()
	}

	// Create garlic message router with router infrastructure
	gr := NewGarlicMessageRouter(
		garlicNetDB,  // NetDB for LeaseSet/RouterInfo lookups
		r.transports, // Transport for sending to peer routers
		tunnelPool,   // Tunnel pool for DESTINATION and TUNNEL delivery
		routerHash,   // Our identity for reflexive routing
	)

	// Set bidirectional references for LOCAL delivery recursion
	gr.SetMessageProcessor(r.messageRouter.GetProcessor())
	r.messageRouter.GetProcessor().SetCloveForwarder(gr)

	// Protect write to garlicRouter field
	r.runMux.Lock()
	r.garlicRouter = gr
	r.runMux.Unlock()

	log.WithFields(logger.Fields{
		"our_hash":        logutil.HashPrefix(routerHash),
		"tunnel_support":  tunnelPool != nil,
		"transport_ready": r.transports != nil,
		"netdb_ready":     r.netdb != nil,
	}).Debug("Garlic message router initialized for non-LOCAL clove forwarding")
}

// wireGarlicSessionManager creates a GarlicSessionManager from the router's X25519
// encryption private key and injects it into the MessageProcessor for decrypting
// inbound garlic messages.
func (r *Router) wireGarlicSessionManager() {
	privKeyBytes := r.keystore.GetEncryptionPrivateKey().Bytes()
	var privKey [32]byte
	copy(privKey[:], privKeyBytes)
	
	// DIAGNOSTIC: Log what private key is being used for garlic decryption
	privKeyHex := fmt.Sprintf("%x", privKey[:8])
	log.WithFields(logger.Fields{
		"at":                      "wireGarlicSessionManager",
		"encryption_privkey_hex":  privKeyHex,
	}).Info("Creating garlic session manager with encryption private key")

	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	if err != nil {
		log.WithError(err).Error("Failed to create garlic session manager — inbound garlic decryption will fail")
		return
	}
	
	// DIAGNOSTIC: Verify the public key that will be used for decryption
	pubKey := garlicMgr.GetPublicKey()
	pubKeyHex := fmt.Sprintf("%x", pubKey[:8])
	log.WithFields(logger.Fields{
		"at":                    "wireGarlicSessionManager",
		"garlic_pubkey_hex":     pubKeyHex,
		"full_pubkey_hex":       fmt.Sprintf("%x", pubKey[:]),
	}).Info("Garlic session manager created - this is the key peers must use to encrypt to us")
	
	r.messageRouter.GetProcessor().SetGarlicSessionManager(garlicMgr)
	if r.tunnelManager != nil {
		r.tunnelManager.SetGarlicKeyRegistrar(garlicMgr)
	}
	log.WithFields(logger.Fields{"at": "wireGarlicSessionManager"}).Debug("Garlic session manager wired into message processor")
}

// getOurRouterHash returns our router's identity hash.
// Returns an error if the hash cannot be computed.
func (r *Router) getOurRouterHash() (common.Hash, error) {
	log.WithField("at", "getOurRouterHash").Debug("constructing RouterInfo to derive identity hash")
	ri, err := r.keystore.ConstructRouterInfo(nil)
	if err != nil {
		return common.Hash{}, oops.Wrapf(err, "failed to construct RouterInfo")
	}
	log.WithField("at", "getOurRouterHash").Debug("RouterInfo constructed, computing IdentHash")

	hash, err := ri.IdentHash()
	if err != nil {
		return common.Hash{}, oops.Wrapf(err, "failed to get IdentHash")
	}
	
	// DIAGNOSTIC: Log the RouterInfo hash to compare with garlic session manager key
	log.WithFields(logger.Fields{
		"at":              "getOurRouterHash",
		"router_info_hash": hash.String()[:16],
	}).Info("Router identity hash computed - peers will look us up with this hash")

	log.WithField("at", "getOurRouterHash").Debug("identity hash computed successfully")
	return hash, nil
}
