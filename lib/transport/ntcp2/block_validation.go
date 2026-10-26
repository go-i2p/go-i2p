package ntcp2

import (
	"fmt"
)

// Block ordering violations enforced during the data phase.
//
// Spec: ntcp2.rst:1455-1469 ("Block Ordering Rules"), quoted from the live
// document:
//   - "Padding, if present, must be the last block." (:1463, restated for the
//     padding block itself at :1742)
//   - "Termination, if present, must be the last block except for Padding."
//     (:1464; the Termination block section repeats it at :1675 as "This must
//     be the last non-padding block in the frame.")
//   - "Multiple Padding blocks are not allowed in a single frame." (:1467)
//
// The spec does not state what a receiver must do with the blocks that precede
// a Termination block; it only says "Drop the connection." (:1674). This
// implementation delivers them first — see [BlockUnframer.ReadNextMessage] and
// its pendingEOFCause field — because :1464 guarantees they precede it and
// :1466 permits multiple I2NP blocks per frame, then closes with reason 0
// ("normal close or unspecified", :1696). Reason 3 is "router shutdown" (:1699),
// which is what this router sends when it initiates the shutdown, not what it
// replies with after receiving one.
//
// This validation lives here, in go-i2p, because go-noise trunk no longer
// provides an equivalent helper: NTCP2PaddingModifier.ValidateAEADFrame was
// removed in go-noise 353292a8be ("fix(ntcp2): correct RH_B semantics, nonce
// ceiling, and drop the deprecated global Transport API"), and even while it
// existed it enforced only the two padding rules, never the Termination rule.
// The inbound data-phase path in trunk strips trailing padding and nothing
// else — NTCP2PaddingModifier.ModifyInbound (ntcp2/padding_modifier.go:133-146)
// delegates to PaddingEngine.RemoveTrailingAEADPadding
// (handshake/padding_engine.go:223) — so no upstream component rejects a
// misordered frame. go-i2p owns the decrypted block list in [BlockUnframer],
// which is where the spec rules are enforced.
//
// The handshake-message ordering rules for msg3p2 (RouterInfo, then Options,
// then Padding) are enforced upstream in go-noise's validateMsg3Part2Blocks
// (ntcp2/handshake_options.go:344-411), so they are deliberately not
// re-implemented here.

// BlockOrderViolation describes a data-phase AEAD frame whose blocks violate
// the spec's Block Ordering Rules.
type BlockOrderViolation struct {
	// Reason is the NTCP2 Termination block reason code the connection
	// should be closed with: 8 (Padding Violation) for padding-rule
	// violations, 10 (Payload Format Error) for a misplaced Termination
	// block. See the reason table at ntcp2.rst:1695-1713 (:1704 padding violation, :1706 payload format error).
	Reason byte
	// Rule is the oops-compatible code identifying which rule was broken.
	Rule string
	// Detail is a human readable description of the violation.
	Detail string
}

const (
	// BlockOrderRuleMultiplePadding is returned when a frame carries more
	// than one Padding block (ntcp2.rst:1467).
	BlockOrderRuleMultiplePadding = "NTCP2_PADDING_MULTIPLE"
	// BlockOrderRulePaddingNotLast is returned when a Padding block is not
	// the last block in the frame (ntcp2.rst:1463, restated at :1742).
	BlockOrderRulePaddingNotLast = "NTCP2_PADDING_NOT_LAST"
	// BlockOrderRuleTerminationNotLast is returned when a Termination block
	// is not the last block in the frame, or is followed only by a Padding
	// block with another block after it (ntcp2.rst:1464, :1675).
	BlockOrderRuleTerminationNotLast = "NTCP2_TERMINATION_NOT_LAST"
)

func (e *BlockOrderViolation) Error() string {
	return fmt.Sprintf("NTCP2 block ordering violation (%s): %s", e.Rule, e.Detail)
}

// TerminationReason returns the NTCP2 Termination block reason code that a
// router should close the connection with for this violation.
func (e *BlockOrderViolation) TerminationReason() byte { return e.Reason }

// ValidateDataPhaseBlockOrder enforces the data-phase Block Ordering Rules
// from ntcp2.rst:1455-1469 against the fully decoded block list of one AEAD
// frame. It returns a *BlockOrderViolation when the frame is malformed and
// nil when the ordering is valid.
func ValidateDataPhaseBlockOrder(blocks []Block) error {
	paddingIdx := -1
	paddingCount := 0
	terminationIdx := -1
	for i := range blocks {
		switch blocks[i].Type {
		case BlockTypePadding:
			if paddingIdx < 0 {
				paddingIdx = i
			}
			paddingCount++
		case BlockTypeTermination:
			if terminationIdx < 0 {
				terminationIdx = i
			}
		}
	}

	last := len(blocks) - 1

	// At most one Padding block per frame (ntcp2.rst:1467).
	if paddingCount > 1 {
		return &BlockOrderViolation{
			Reason: TerminationPaddingViolation,
			Rule:   BlockOrderRuleMultiplePadding,
			Detail: fmt.Sprintf("frame contains %d padding blocks; at most one is allowed", paddingCount),
		}
	}

	// A Padding block, when present, must be the last block in the frame
	// (ntcp2.rst:1463, restated for the data phase at :1742). This
	// covers [Padding, Termination]: the padding is not last, which the
	// padding rule forbids regardless of where the termination sits.
	if paddingIdx >= 0 && paddingIdx != last {
		return &BlockOrderViolation{
			Reason: TerminationPaddingViolation,
			Rule:   BlockOrderRulePaddingNotLast,
			Detail: fmt.Sprintf("padding block at position %d is not the last block in the frame", paddingIdx),
		}
	}

	// A Termination block must be last, or second to last when followed by
	// the frame's single Padding block (ntcp2.rst:1464, :1675).
	if terminationIdx >= 0 {
		allowed := terminationIdx == last ||
			(terminationIdx == last-1 && paddingIdx == last)
		if !allowed {
			return &BlockOrderViolation{
				Reason: TerminationPayloadFormatError,
				Rule:   BlockOrderRuleTerminationNotLast,
				Detail: fmt.Sprintf("termination block at position %d is not the last block in the frame", terminationIdx),
			}
		}
	}

	return nil
}

// BlockOrderTerminationReason maps a block-ordering error to the NTCP2
// Termination block reason code to close the connection with (8 = Padding
// Violation, 10 = Payload Format Error; ntcp2.rst:1704, :1706).
func BlockOrderTerminationReason(err error) byte {
	if v, ok := err.(*BlockOrderViolation); ok {
		return v.Reason
	}
	return TerminationPayloadFormatError
}
