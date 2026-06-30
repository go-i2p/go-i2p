package ntcp2

import (
	"encoding/binary"
)

// Termination reason codes per the NTCP2 specification.
// These are used in the termination block (block type 0x04) to indicate
// why the session is being closed.
//
// Spec reference: https://geti2p.net/spec/ntcp2#termination
const (
	// TerminationNormalClose indicates a graceful session shutdown.
	TerminationNormalClose byte = 0

	// TerminationOppositeDirectionTerminated indicates a Termination block was
	// received from the peer; this router is responding with its own termination.
	TerminationOppositeDirectionTerminated byte = 1

	// TerminationIdleTimeout indicates the session was terminated due to inactivity.
	TerminationIdleTimeout byte = 2

	// TerminationRouterShutdown indicates the router is shutting down.
	TerminationRouterShutdown byte = 3

	// TerminationAEADFailure indicates an AEAD decryption failure in the data phase.
	// When this is the reason, the termination block MUST NOT be sent if the cipher
	// state may be corrupted — only probing-resistance junk-read should be performed.
	TerminationAEADFailure byte = 4

	// TerminationIncompatibleOptions indicates an error in the session options negotiation
	// (version, network ID, or option values are incompatible).
	TerminationIncompatibleOptions byte = 5

	// TerminationIncompatibleSignatureType indicates the peer uses a signature type
	// that this router does not support.
	TerminationIncompatibleSignatureType byte = 6

	// TerminationClockSkew indicates the peer's timestamp is too far from local time.
	TerminationClockSkew byte = 7

	// TerminationPaddingViolation indicates padding rules were violated.
	TerminationPaddingViolation byte = 8

	// TerminationAEADFramingError indicates an AEAD framing error (e.g. wrong frame length).
	TerminationAEADFramingError byte = 9

	// TerminationPayloadFormatError indicates the payload format was invalid.
	TerminationPayloadFormatError byte = 10

	// TerminationMsg1DecryptionFailure indicates message 1 (handshake) decryption failed.
	TerminationMsg1DecryptionFailure byte = 11

	// TerminationMsg2DecryptionFailure indicates message 2 (handshake) decryption failed.
	TerminationMsg2DecryptionFailure byte = 12

	// TerminationMsg3Error indicates an error processing message 3 of the handshake
	// (decryption failure or invalid contents). Matches i2pd eNTCP2Message3Error.
	TerminationMsg3Error byte = 13

	// TerminationIntraFrameReadTimeout indicates a timeout while reading a frame
	// during the data phase. Matches i2pd eNTCP2IntraFrameReadTimeout.
	TerminationIntraFrameReadTimeout byte = 14

	// TerminationRouterInfoSignatureVerificationFail indicates the peer's RouterInfo
	// signature verification failed. Matches i2pd eNTCP2RouterInfoSignatureVerificationFail.
	TerminationRouterInfoSignatureVerificationFail byte = 15

	// TerminationIncorrectSParameter indicates the static key (the Noise "s" parameter)
	// is incorrect — e.g. it does not match the encryption key published in the peer's
	// RouterInfo. Matches i2pd eNTCP2IncorrectSParameter.
	TerminationIncorrectSParameter byte = 16

	// TerminationBanned indicates the peer is banned. Matches i2pd eNTCP2Banned.
	TerminationBanned byte = 17
)

// terminationBlockType is the NTCP2 data-phase block type for termination.
const terminationBlockType byte = 0x04

// terminationBlockPayloadSize is the size of the termination block payload per spec:
//
//	session duration (8 bytes, big-endian uint64) + reason code (1 byte) = 9 bytes
//
// Spec reference: https://geti2p.net/spec/ntcp2#blk-termination
const terminationBlockPayloadSize = 9

// terminationBlockHeaderSize is the block type (1 byte) + size (2 bytes) = 3 bytes
const terminationBlockHeaderSize = 3

// terminationBlockTotalSize is the total size of the termination block including header.
const terminationBlockTotalSize = terminationBlockHeaderSize + terminationBlockPayloadSize

// BuildTerminationBlock constructs a termination block payload suitable for
// sending through NTCP2Conn.Write, which will encrypt it with the session's
// Noise cipher state and apply SipHash length obfuscation.
//
// The termination block format per NTCP2 spec is:
//
//	[type:1=0x04][size:2=0x0009][sessionDuration:8][reason:1]
//
// Total: 12 bytes (3 header + 9 payload).
// sessionDuration is elapsed seconds since the session was established; zero is
// acceptable when the caller does not track session start time.
func BuildTerminationBlock(reason byte) []byte {
	block := make([]byte, terminationBlockTotalSize)

	// Block type
	block[0] = terminationBlockType

	// Payload size (big-endian 16-bit)
	binary.BigEndian.PutUint16(block[1:3], uint16(terminationBlockPayloadSize))

	// Session duration (8 bytes, big-endian uint64). We use 0 as a conservative
	// default; the spec only requires the field to be present.
	binary.BigEndian.PutUint64(block[3:11], 0)

	// Reason code
	block[11] = reason

	return block
}

// TerminationReasonString returns a human-readable string for a termination
// reason code received from a peer. The descriptions match i2pd's definitions.
func TerminationReasonString(reason byte) string {
	switch reason {
	case TerminationNormalClose:
		return "normal close"
	case TerminationOppositeDirectionTerminated:
		return "opposite direction terminated"
	case TerminationIdleTimeout:
		return "idle timeout"
	case TerminationRouterShutdown:
		return "router shutdown"
	case TerminationAEADFailure:
		return "data-phase AEAD failure"
	case TerminationIncompatibleOptions:
		return "incompatible options"
	case TerminationIncompatibleSignatureType:
		return "incompatible signature type"
	case TerminationClockSkew:
		return "clock skew"
	case TerminationPaddingViolation:
		return "padding violation"
	case TerminationAEADFramingError:
		return "AEAD framing error"
	case TerminationPayloadFormatError:
		return "payload format error"
	case TerminationMsg1DecryptionFailure:
		return "message 1 decryption failure"
	case TerminationMsg2DecryptionFailure:
		return "message 2 decryption failure"
	case TerminationMsg3Error:
		return "message 3 error"
	case TerminationIntraFrameReadTimeout:
		return "intra-frame read timeout"
	case TerminationRouterInfoSignatureVerificationFail:
		return "RouterInfo signature verification failed"
	case TerminationIncorrectSParameter:
		return "incorrect s parameter (static key)"
	case TerminationBanned:
		return "banned"
	default:
		return "unknown"
	}
}

// IsAEADFailureReason returns true if the given reason code indicates an AEAD
// decryption failure, in which case the cipher state may be corrupted and the
// termination block MUST NOT be sent encrypted (only junk-read for probing
// resistance).
func IsAEADFailureReason(reason byte) bool {
	return reason == TerminationAEADFailure
}
