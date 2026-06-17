package i2np

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/tunnel/build"
	"github.com/go-i2p/logger"
)

// buildExpireGrace is the extra window added to the cleanup timer and expiry
// threshold to close the race between a late-arriving reply and the
// time.AfterFunc cleanup goroutine (BUG-5 fix).
const buildExpireGrace = 200 * time.Millisecond

// buildRequest tracks a pending tunnel build request for correlation with replies.
// This enables matching build replies to the original request and managing timeouts.
type buildRequest struct {
	tunnelID        tunnel.TunnelID          // Unique tunnel ID for this request
	messageID       int                      // I2NP message ID for correlation
	replyTunnelID   tunnel.TunnelID          // Reply tunnel ID selected for outbound build replies
	hopCount        int                      // Number of hops in the tunnel
	replyKeys       []session_key.SessionKey // Reply decryption keys for each hop
	replyIVs        [][16]byte               // Reply IVs for each hop
	noiseHashes     [][32]byte               // STBM per-hop Noise transcript hashes for reply AEAD decryption
	createdAt       time.Time                // When the request was created
	retryCount      int                      // Number of retry attempts
	useShortBuild   bool                     // True if using STBM, false for legacy VTB
	isInbound       bool                     // True if this is an inbound tunnel
	isClientTunnel  bool                     // True if this tunnel belongs to an I2CP client session
	clientSessionID uint16                   // Session ID if isClientTunnel=true; 0 otherwise
}

// expiredBuild tracks a recently expired build request for late-reply accounting.
// Entries are retained briefly so uncorrelated late replies can be attributed to
// their original build origin (exploratory vs client) for metrics correction.
type expiredBuild struct {
	req       *buildRequest
	expiredAt time.Time
}

// TunnelManager coordinates tunnel building and management
type TunnelManager struct {
	inboundPool      *tunnel.Pool
	outboundPool     *tunnel.Pool
	sessionProvider  SessionProvider
	buildSessionProv build.BuildSessionProvider // Adapter for lib/tunnel/build
	messageFactory   build.BuildMessageFactory  // Creates serialized I2NP tunnel build messages
	peerSelector     tunnel.PeerSelector
	pendingBuilds    map[int]*buildRequest // Track pending builds by message ID
	expiredBuilds    map[int]expiredBuild  // Recently expired builds retained for late-reply accounting
	buildMutex       sync.RWMutex          // Protect pending builds map
	cleanupTicker    *time.Ticker          // Periodic cleanup of expired requests
	cleanupStop      chan struct{}         // Signal to stop cleanup goroutine
	cleanupOnce      sync.Once             // Ensures cleanup goroutine starts at most once
	stopOnce         sync.Once             // Ensures Stop() is idempotent (no double-close panic)
	replyProcessor   *ReplyProcessor       // Handles reply decryption and processing
	// garlicKeyRegistrar receives one-time garlic keys derived from STBM Noise
	// transcript hashes so that incoming ShortTunnelBuildReply garlic messages
	// can be decrypted. Set via SetGarlicKeyRegistrar after construction.
	garlicKeyRegistrar GarlicKeyRegistrar

	// inboundHandler is called after a successful inbound tunnel build to register
	// the tunnel as a control-plane (exploratory) endpoint so that TunnelData
	// messages delivered via TUNNEL delivery mode are not silently dropped.
	// Set via SetInboundHandler after construction.
	inboundHandler InboundHandlerRegistrar

	// Build event windows for period-aware statistics (retained for 2 hours).
	// These track tunnel build outcomes so GetRate("tunnel.buildExploratorySuccess", period)
	// can return the count of successful builds within the requested time window.
	buildSuccessWindow       *buildEventWindow // successful exploratory tunnel builds
	buildRejectWindow        *buildEventWindow // explicitly rejected tunnel builds
	buildExpireWindow        *buildEventWindow // timed-out tunnel builds
	buildTimeWindow          *buildEventWindow // build duration in milliseconds
	clientBuildSuccessWindow *buildEventWindow // successful I2CP client session tunnel builds
	clientBuildRejectWindow  *buildEventWindow // rejected I2CP client session tunnel builds
	clientBuildExpireWindow  *buildEventWindow // timed-out I2CP client session tunnel builds
}

// NewTunnelManager creates a new tunnel manager with build request tracking.
// The background cleanup goroutine is started lazily on the first build request,
// avoiding resource leaks if the TunnelManager is created but never used.
// Creates separate inbound and outbound tunnel pools for proper statistics tracking.
func NewTunnelManager(peerSelector tunnel.PeerSelector) *TunnelManager {
	// Create separate pools for inbound and outbound tunnels
	inboundConfig := tunnel.DefaultPoolConfig()
	inboundConfig.IsInbound = true
	inboundPool := tunnel.NewTunnelPoolWithConfig(peerSelector, inboundConfig)

	outboundConfig := tunnel.DefaultPoolConfig()
	outboundConfig.IsInbound = false
	outboundPool := tunnel.NewTunnelPoolWithConfig(peerSelector, outboundConfig)

	const buildWindowMaxAge = 2 * time.Hour
	tm := &TunnelManager{
		inboundPool:              inboundPool,
		outboundPool:             outboundPool,
		peerSelector:             peerSelector,
		pendingBuilds:            make(map[int]*buildRequest),
		expiredBuilds:            make(map[int]expiredBuild),
		cleanupStop:              make(chan struct{}),
		buildSuccessWindow:       newBuildEventWindow(buildWindowMaxAge),
		buildRejectWindow:        newBuildEventWindow(buildWindowMaxAge),
		buildExpireWindow:        newBuildEventWindow(buildWindowMaxAge),
		buildTimeWindow:          newBuildEventWindow(buildWindowMaxAge),
		clientBuildSuccessWindow: newBuildEventWindow(buildWindowMaxAge),
		clientBuildRejectWindow:  newBuildEventWindow(buildWindowMaxAge),
		clientBuildExpireWindow:  newBuildEventWindow(buildWindowMaxAge),
		messageFactory:           NewBuildMessageFactory(),
	}

	// Initialize ReplyProcessor with default config for reply decryption
	tm.replyProcessor = NewReplyProcessor(DefaultReplyProcessorConfig(), tm)
	replyTunnelProvider := func() (tunnel.TunnelID, bool) {
		if tm.inboundPool == nil {
			return 0, false
		}
		if inbound := tm.inboundPool.SelectTunnel(); inbound != nil {
			return inbound.ID, true
		}
		return 0, false
	}
	tm.inboundPool.SetReplyTunnelProvider(replyTunnelProvider)
	tm.outboundPool.SetReplyTunnelProvider(replyTunnelProvider)

	// Wire retry callback for both pools: tunnel build timeouts will automatically retry
	tm.replyProcessor.SetRetryCallback(tm.retryTunnelBuild)

	log.WithFields(logger.Fields{
		"at":     "NewTunnelManager",
		"phase":  "initialization",
		"reason": "retry callback configured for automatic tunnel build retry",
	}).Debug("tunnel manager initialized with retry callback")

	// Cleanup goroutine is started lazily via ensureCleanupStarted()
	// to avoid resource leaks when TunnelManager is created but never used.

	log.WithFields(logger.Fields{
		"at":     "NewTunnelManager",
		"phase":  "initialization",
		"reason": "tunnel manager initialized with separate inbound/outbound pools",
	}).Debug("tunnel manager created")

	return tm
}

// ensureCleanupStarted lazily starts the background cleanup goroutine.
// Safe to call multiple times; the goroutine is started at most once.
func (tm *TunnelManager) ensureCleanupStarted() {
	tm.cleanupOnce.Do(func() {
		tm.cleanupTicker = time.NewTicker(30 * time.Second)
		go tm.cleanupExpiredBuilds()
		log.WithFields(logger.Fields{"at": "ensureCleanupStarted"}).Debug("Tunnel manager cleanup goroutine started (lazy)")
	})
}

// SetGarlicKeyRegistrar wires the GarlicKeyRegistrar so that one-time garlic
// reply keys derived from STBM builds can be registered for later decryption.
// Must be called before the first tunnel build is initiated.
func (tm *TunnelManager) SetGarlicKeyRegistrar(r GarlicKeyRegistrar) {
	tm.garlicKeyRegistrar = r
}

// SetInboundHandler wires the InboundHandlerRegistrar so that newly-active
// inbound tunnels are registered as control-plane (exploratory) endpoints.
// Must be called before tunnel builds begin.
func (tm *TunnelManager) SetInboundHandler(h InboundHandlerRegistrar) {
	tm.inboundHandler = h
}

// Stop gracefully stops the tunnel manager and cleans up resources.
// Safe to call multiple times — subsequent calls are no-ops.
// Should be called when shutting down the router.
func (tm *TunnelManager) Stop() {
	tm.stopOnce.Do(func() {
		if tm.cleanupTicker != nil {
			tm.cleanupTicker.Stop()
		}
		close(tm.cleanupStop)

		if tm.inboundPool != nil {
			tm.inboundPool.Stop()
		}
		if tm.outboundPool != nil {
			tm.outboundPool.Stop()
		}

		log.WithFields(logger.Fields{"at": "Stop"}).Debug("Tunnel manager stopped")
	})
}

// SetSessionProvider sets the session provider for sending tunnel build messages
func (tm *TunnelManager) SetSessionProvider(provider SessionProvider) {
	tm.sessionProvider = provider
	// Also set up the adapted build.SessionProvider
	tm.buildSessionProv = NewBuildSessionProvider(provider)
}

// SetMessageFactory sets the factory for creating serialized I2NP tunnel build messages.
// Must be called before tunnel building begins.
func (tm *TunnelManager) SetMessageFactory(factory build.BuildMessageFactory) {
	tm.messageFactory = factory
}

// SetPeerSelector replaces the peer selector and rebuilds the tunnel pools.
// If pools are already active they are stopped before the new ones are created.
func (tm *TunnelManager) SetPeerSelector(selector tunnel.PeerSelector) {
	tm.peerSelector = selector
	if tm.inboundPool != nil || tm.outboundPool != nil {
		if tm.inboundPool != nil {
			tm.inboundPool.Stop()
		}
		if tm.outboundPool != nil {
			tm.outboundPool.Stop()
		}
		inboundConfig := tunnel.DefaultPoolConfig()
		inboundConfig.IsInbound = true
		tm.inboundPool = tunnel.NewTunnelPoolWithConfig(selector, inboundConfig)

		outboundConfig := tunnel.DefaultPoolConfig()
		outboundConfig.IsInbound = false
		tm.outboundPool = tunnel.NewTunnelPoolWithConfig(selector, outboundConfig)
	}
}

// SetOurRouterHash propagates our router's identity hash to both tunnel pools
// so they can populate the ReplyGateway field in build requests. Without this,
// the last hop in every tunnel build sends its reply to an all-zeros peer and
// the reply is never received.
func (tm *TunnelManager) SetOurRouterHash(hash common.Hash) {
	if tm.inboundPool != nil {
		tm.inboundPool.SetRouterHash(hash)
	}
	if tm.outboundPool != nil {
		tm.outboundPool.SetRouterHash(hash)
	}
}
