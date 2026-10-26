package ntcp2

import (
	"fmt"
)

// Block ordering violations enforced during the data phase.
//
// Spec: ntcp2.rst:1455-1469 ("Block Ordering Rules") and :1675 / :1742:
//   - "There must be at most one Padding block per AEAD frame" (:1462-1463)
//   - "If there is a Padding block, it must be the last block in the frame" (:1463-1464,
//     restated for the data phase at :1742)
//   - "If there is a Termination block, it must be the last block in the frame,
//     unless there is a Padding block, in which case the Termination block must
//     be the second to last block" (:1465-1469; the Termination block spec at
//     :1675 refers back to these rules)
//
// A receiver that gets a Termination block must process the blocks before it
// and then close the connection with reason 3 (Normal Close) — :1730-1731,
// which the session receive path does.
//
// This validation lives here, in go-i2p, because the equivalent upstream
// helper is not reachable from outside go-noise: go-noise exposes
// ValidateAEADFrame in ntcp2/padding_modifier.go:316, but it has zero
// non-test callers — the inbound modifier chain only calls
// RemoveTrailingAEADPadding (padding_modifier.go:134-151), and the padding
// modifier instance is created privately inside Config.setupNTCP2Modifiers
// (config.go:796-830) with no accessor. Custom modifiers registered with
// WithModifiers run before the standard ones on the inbound path
// (modifier_chain.go:102-113), i.e. before the padding is stripped, so they
// cannot see the final block list either. go-i2p owns the decrypted block
// list in BlockUnframer, so that is where the spec rules are enforced.
// (Reported upstream as a defect: ValidateAEADFrame is dead code.)
//
// The handshake-message ordering rules for msg3p2 (Router Info, then Options,
// then Padding) are enforced upstream in go-noise's
// validateMsg3Part2Blocks (ntcp2/handshake_options.go:344-411), so they are
// deliberately not re-implemented here.

// BlockOrderViolation describes a data-phase AEAD frame whose blocks violate
// the spec's Block Ordering Rules.
type BlockOrderViolation struct {
	// Reason is the NTCP2 Termination block reason code the connection
	// should be closed with: 8 (Padding Violation) for padding-rule
	// violations, 10 (Payload Format Error) for a misplaced Termination
	// block. See ntcp2.rst:1730-1760.
	Reason byte
	// Rule is the oops-compatible code identifying which rule was broken.
	Rule string
	// Detail is a human readable description of the violation.
	Detail string
}

const (
	// BlockOrderRuleMultiplePadding is returned when a frame carries more
	// than one Padding block (ntcp2.rst:1462-1463).
	BlockOrderRuleMultiplePadding = "NTCP2_PADDING_MULTIPLE"
	// BlockOrderRulePaddingNotLast is returned when a Padding block is not
	// the last block in the frame (ntcp2.rst:1463-1464, :1742).
	BlockOrderRulePaddingNotLast = "NTCP2_PADDING_NOT_LAST"
	// BlockOrderRuleTerminationNotLast is returned when a Termination block
	// is not the last block in the frame, or is followed only by a Padding
	// block with another block after it (ntcp2.rst:1465-1469).
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

	// At most one Padding block per frame (ntcp2.rst:1462-1463).
	if paddingCount > 1 {
		return &BlockOrderViolation{
			Reason: TerminationPaddingViolation,
			Rule:   BlockOrderRuleMultiplePadding,
			Detail: fmt.Sprintf("frame contains %d padding blocks; at most one is allowed", paddingCount),
		}
	}

	// A Padding block, when present, must be the last block in the frame
	// (ntcp2.rst:1463-1464, restated for the data phase at :1742). This
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
	// the frame's single Padding block (ntcp2.rst:1465-1469).
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
// Violation, 10 = Payload Format Error; ntcp2.rst:1751-1755).
func BlockOrderTerminationReason(err error) byte {
	if v, ok := err.(*BlockOrderViolation); ok {
		return v.Reason
	}
	return TerminationPayloadFormatError
}
