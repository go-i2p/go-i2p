package i2np

import "sync/atomic"

// ExploratoryReplyStage identifies checkpoints in the exploratory reply funnel.
// L-5 Consolidation: Typed enum instead of string constants for type-safe dispatch.
type ExploratoryReplyStage int

const (
	ExploratoryReplyStageInboundI2NPReceived ExploratoryReplyStage = iota
	ExploratoryReplyStageTunnelGatewayParsed
	ExploratoryReplyStageGarlicDecryptAttempt
	ExploratoryReplyStageGarlicDecryptSuccess
	ExploratoryReplyStageShortReplyDispatched
	ExploratoryReplyStageShortReplyCorrelated
	ExploratoryReplyStageShortReplyUncorrelated
	ExploratoryReplyStageLateReplyReclassedOK
	ExploratoryReplyStageLateReplyReclassedFail
	ExploratoryReplyStageLateReplyShortSkipped
)

// stageNames maps ExploratoryReplyStage to string keys for reporting
var stageNames = map[ExploratoryReplyStage]string{
	ExploratoryReplyStageInboundI2NPReceived:    "inbound_i2np_received",
	ExploratoryReplyStageTunnelGatewayParsed:    "tunnel_gateway_inner_parsed",
	ExploratoryReplyStageGarlicDecryptAttempt:   "garlic_decrypt_attempted",
	ExploratoryReplyStageGarlicDecryptSuccess:   "garlic_decrypt_succeeded",
	ExploratoryReplyStageShortReplyDispatched:   "short_build_reply_dispatched",
	ExploratoryReplyStageShortReplyCorrelated:   "short_build_reply_correlated",
	ExploratoryReplyStageShortReplyUncorrelated: "short_build_reply_uncorrelated",
	ExploratoryReplyStageLateReplyReclassedOK:   "late_reply_reclassified_success",
	ExploratoryReplyStageLateReplyReclassedFail: "late_reply_reclassified_reject",
	ExploratoryReplyStageLateReplyShortSkipped:  "late_reply_short_build_skipped",
}

var exploratoryReplyCounters = struct {
	inboundI2NPReceived    atomic.Uint64
	tunnelGatewayParsed    atomic.Uint64
	garlicDecryptAttempted atomic.Uint64
	garlicDecryptSucceeded atomic.Uint64
	shortReplyDispatched   atomic.Uint64
	shortReplyCorrelated   atomic.Uint64
	shortReplyUncorrelated atomic.Uint64
	lateReplyReclassedOK   atomic.Uint64
	lateReplyReclassedFail atomic.Uint64
	lateReplyShortSkipped  atomic.Uint64
}{}

// stageToCounter maps ExploratoryReplyStage to its atomic counter.
var stageToCounter = map[ExploratoryReplyStage]*atomic.Uint64{
	ExploratoryReplyStageInboundI2NPReceived:    &exploratoryReplyCounters.inboundI2NPReceived,
	ExploratoryReplyStageTunnelGatewayParsed:    &exploratoryReplyCounters.tunnelGatewayParsed,
	ExploratoryReplyStageGarlicDecryptAttempt:   &exploratoryReplyCounters.garlicDecryptAttempted,
	ExploratoryReplyStageGarlicDecryptSuccess:   &exploratoryReplyCounters.garlicDecryptSucceeded,
	ExploratoryReplyStageShortReplyDispatched:   &exploratoryReplyCounters.shortReplyDispatched,
	ExploratoryReplyStageShortReplyCorrelated:   &exploratoryReplyCounters.shortReplyCorrelated,
	ExploratoryReplyStageShortReplyUncorrelated: &exploratoryReplyCounters.shortReplyUncorrelated,
	ExploratoryReplyStageLateReplyReclassedOK:   &exploratoryReplyCounters.lateReplyReclassedOK,
	ExploratoryReplyStageLateReplyReclassedFail: &exploratoryReplyCounters.lateReplyReclassedFail,
	ExploratoryReplyStageLateReplyShortSkipped:  &exploratoryReplyCounters.lateReplyShortSkipped,
}

// RecordExploratoryReplyStage increments a stage counter used to audit the
// exploratory reply funnel from transport ingress through reply correlation.
func RecordExploratoryReplyStage(stage ExploratoryReplyStage) {
	if counter, ok := stageToCounter[stage]; ok {
		counter.Add(1)
	}
}

// SnapshotExploratoryReplyStages returns current exploratory reply funnel counters.
func SnapshotExploratoryReplyStages() map[string]uint64 {
	result := make(map[string]uint64)
	for stage, name := range stageNames {
		if counter, ok := stageToCounter[stage]; ok {
			result[name] = counter.Load()
		}
	}
	return result
}
