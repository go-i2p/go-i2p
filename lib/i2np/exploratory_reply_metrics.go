package i2np

import "sync/atomic"

const (
	// ExploratoryReplyStage* constants identify checkpoints in the exploratory reply funnel.
	ExploratoryReplyStageInboundI2NPReceived    = "inbound_i2np_received"
	ExploratoryReplyStageTunnelGatewayParsed    = "tunnel_gateway_inner_parsed"
	ExploratoryReplyStageGarlicDecryptAttempt   = "garlic_decrypt_attempted"
	ExploratoryReplyStageGarlicDecryptSuccess   = "garlic_decrypt_succeeded"
	ExploratoryReplyStageShortReplyDispatched   = "short_build_reply_dispatched"
	ExploratoryReplyStageShortReplyCorrelated   = "short_build_reply_correlated"
	ExploratoryReplyStageShortReplyUncorrelated = "short_build_reply_uncorrelated"
)

var exploratoryReplyCounters = struct {
	inboundI2NPReceived    atomic.Uint64
	tunnelGatewayParsed    atomic.Uint64
	garlicDecryptAttempted atomic.Uint64
	garlicDecryptSucceeded atomic.Uint64
	shortReplyDispatched   atomic.Uint64
	shortReplyCorrelated   atomic.Uint64
	shortReplyUncorrelated atomic.Uint64
}{}

// RecordExploratoryReplyStage increments a stage counter used to audit the
// exploratory reply funnel from transport ingress through reply correlation.
func RecordExploratoryReplyStage(stage string) {
	switch stage {
	case ExploratoryReplyStageInboundI2NPReceived:
		exploratoryReplyCounters.inboundI2NPReceived.Add(1)
	case ExploratoryReplyStageTunnelGatewayParsed:
		exploratoryReplyCounters.tunnelGatewayParsed.Add(1)
	case ExploratoryReplyStageGarlicDecryptAttempt:
		exploratoryReplyCounters.garlicDecryptAttempted.Add(1)
	case ExploratoryReplyStageGarlicDecryptSuccess:
		exploratoryReplyCounters.garlicDecryptSucceeded.Add(1)
	case ExploratoryReplyStageShortReplyDispatched:
		exploratoryReplyCounters.shortReplyDispatched.Add(1)
	case ExploratoryReplyStageShortReplyCorrelated:
		exploratoryReplyCounters.shortReplyCorrelated.Add(1)
	case ExploratoryReplyStageShortReplyUncorrelated:
		exploratoryReplyCounters.shortReplyUncorrelated.Add(1)
	}
}

// SnapshotExploratoryReplyStages returns current exploratory reply funnel counters.
func SnapshotExploratoryReplyStages() map[string]uint64 {
	return map[string]uint64{
		ExploratoryReplyStageInboundI2NPReceived:    exploratoryReplyCounters.inboundI2NPReceived.Load(),
		ExploratoryReplyStageTunnelGatewayParsed:    exploratoryReplyCounters.tunnelGatewayParsed.Load(),
		ExploratoryReplyStageGarlicDecryptAttempt:   exploratoryReplyCounters.garlicDecryptAttempted.Load(),
		ExploratoryReplyStageGarlicDecryptSuccess:   exploratoryReplyCounters.garlicDecryptSucceeded.Load(),
		ExploratoryReplyStageShortReplyDispatched:   exploratoryReplyCounters.shortReplyDispatched.Load(),
		ExploratoryReplyStageShortReplyCorrelated:   exploratoryReplyCounters.shortReplyCorrelated.Load(),
		ExploratoryReplyStageShortReplyUncorrelated: exploratoryReplyCounters.shortReplyUncorrelated.Load(),
	}
}
