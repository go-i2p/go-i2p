package i2np

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// TunnelOrchestrator defines the interface for the tunnel build coordinator.
// It captures the full public surface of TunnelManager consumed from outside
// lib/i2np, providing the extension seam needed to inject alternative
// implementations (e.g. a deterministic test builder or a future variant
// that decouples build orchestration from the I2NP wire-format layer).
//
// TunnelOrchestrator structurally satisfies:
//   - tunnel.BuilderInterface    (BuildTunnel — used by i2cp.Server.SetTunnelBuilder)
//   - TunnelBuildReplyProcessor  (ProcessTunnelBuildReply — used by MessageProcessor)
type TunnelOrchestrator interface {
	// Pool access
	GetPool() *tunnel.Pool
	GetInboundPool() *tunnel.Pool
	GetOutboundPool() *tunnel.Pool

	// Lifecycle
	Stop()

	// Configuration
	SetOurRouterHash(hash common.Hash)
	SetGarlicKeyRegistrar(r GarlicKeyRegistrar)
	SetSessionProvider(provider SessionProvider)
	SetPeerSelector(selector tunnel.PeerSelector)

	// Build operations — structurally satisfies tunnel.BuilderInterface
	BuildTunnel(req tunnel.BuildTunnelRequest) (*tunnel.BuildTunnelResult, error)
	BuildTunnelFromRequest(req tunnel.BuildTunnelRequest) (tunnel.TunnelID, []common.Hash, error)
	BuildTunnelWithBuilder(builder TunnelBuilder) error

	// Reply processing — structurally satisfies TunnelBuildReplyProcessor
	ProcessTunnelBuildReply(handler TunnelReplyHandler, messageID int) error
	ProcessTunnelReply(handler TunnelReplyHandler, messageID int) error

	// Metrics
	GetBuildSuccessCount(windowMs int64) float64
	GetBuildRejectCount(windowMs int64) float64
	GetBuildExpireCount(windowMs int64) float64
	GetBuildAvgTimeMs(windowMs int64) float64
	GetClientBuildSuccessCount(windowMs int64) float64
	GetClientBuildRejectCount(windowMs int64) float64
	GetClientBuildExpireCount(windowMs int64) float64
}

// Compile-time assertion: *TunnelManager must fully implement TunnelOrchestrator.
var _ TunnelOrchestrator = (*TunnelManager)(nil)
