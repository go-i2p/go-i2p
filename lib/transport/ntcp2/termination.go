package ntcp2

import (
	"encoding/binary"
	"time"
)

// Termination reason codes per the NTCP2 specification.
// These are used in the termination block (block type 0x04) to indicate
// why the session is being closed.
//
// Spec reference: https://geti2p.net/spec/ntcp2#termination
const (
	// TerminationNormalClose indicates a graceful session shutdown.
	TerminationNormalClose byte = 0

	// TerminationRouterUpdated indicates the router's RouterInfo has been updated
	// and the peer should re-fetch it.
	TerminationRouterUpdated byte = 1

	// TerminationAEADFrameError indicates an AEAD decryption failure in the data phase.
	// When this is the reason, the termination block MUST NOT be sent if the cipher
	// state may be corrupted — only probing-resistance junk-read should be performed.
	TerminationAEADFrameError byte = 4

	// TerminationOptionsError indicates an error in the session options negotiation.
	TerminationOptionsError byte = 5

	// TerminationSignatureError indicates a signature verification failure.
	TerminationSignatureError byte = 6

	// TerminationFrameTimeout indicates the peer did not send a frame within
	// the expected time.
	TerminationFrameTimeout byte = 11

	// TerminationPayloadFormatError indicates the payload format was invalid.
	TerminationPayloadFormatError byte = 12

	// TerminationMessage1Error indicates an error during Noise handshake message 1.
	TerminationMessage1Error byte = 13

	// TerminationMessage2Error indicates an error during Noise handshake message 2.
	TerminationMessage2Error byte = 14

	// TerminationMessage3Error indicates an error during Noise handshake message 3.
	TerminationMessage3Error byte = 15

	// TerminationFrameLengthOutOfRange indicates the frame length was outside
	// the allowed range.
	TerminationFrameLengthOutOfRange byte = 16

	// TerminationPaddingViolation indicates padding rules were violated.
	TerminationPaddingViolation byte = 17
)

// terminationBlockType is the NTCP2 data-phase block type for termination.
const terminationBlockType byte = 0x04

// terminationBlockPayloadSize is the size of the termination block payload:
//
//	version (4 bytes) + networkID (1 byte) + time (4 bytes) + reason (1 byte) = 10 bytes
const terminationBlockPayloadSize = 10

// terminationBlockHeaderSize is the block type (1 byte) + size (2 bytes) = 3 bytes
const terminationBlockHeaderSize = 3

// terminationBlockTotalSize is the total size of the termination block including header.
const terminationBlockTotalSize = terminationBlockHeaderSize + terminationBlockPayloadSize

// i2pVersion is the I2P router version announced in termination blocks.
// This should match the version of the I2P specification we implement.
var i2pVersion = [4]byte{0, 9, 67, 0} // 0.9.67

// i2pNetworkID is the I2P network identifier (2 = main network).
const i2pNetworkID byte = 2

// BuildTerminationBlock constructs a termination block payload suitable for
// sending through NTCP2Conn.Write, which will encrypt it with the session's
// Noise cipher state and apply SipHash length obfuscation.
//
// The termination block format is:
//
//	[type:1=0x04][size:2][version:4][networkID:1][time:4][reason:1]
//
// Total: 13 bytes (3 header + 10 payload).
func BuildTerminationBlock(reason byte) []byte {
	block := make([]byte, terminationBlockTotalSize)

	// Block type
	block[0] = terminationBlockType

	// Payload size (big-endian 16-bit)
	binary.BigEndian.PutUint16(block[1:3], uint16(terminationBlockPayloadSize))

	// Version (4 bytes, big-endian)
	copy(block[3:7], i2pVersion[:])

	// Network ID
	block[7] = i2pNetworkID

	// Timestamp (seconds since epoch, big-endian 32-bit)
	binary.BigEndian.PutUint32(block[8:12], uint32(time.Now().Unix()))

	// Reason code
	block[12] = reason

	return block
}

// TerminationReasonString returns a human-readable string for a termination reason code.
func TerminationReasonString(reason byte) string {
	switch reason {
	case TerminationNormalClose:
		return "normal close"
	case TerminationRouterUpdated:
		return "router updated"
	case TerminationAEADFrameError:
		return "AEAD frame error"
	case TerminationOptionsError:
		return "options error"
	case TerminationSignatureError:
		return "signature error"
	case TerminationFrameTimeout:
		return "frame timeout"
	case TerminationPayloadFormatError:
		return "payload format error"
	case TerminationMessage1Error:
		return "message 1 error"
	case TerminationMessage2Error:
		return "message 2 error"
	case TerminationMessage3Error:
		return "message 3 error"
	case TerminationFrameLengthOutOfRange:
		return "frame length out of range"
	case TerminationPaddingViolation:
		return "padding violation"
	default:
		return "unknown"
	}
}

// IsAEADFailureReason returns true if the given reason code indicates an AEAD
// decryption failure, in which case the cipher state may be corrupted and the
// termination block MUST NOT be sent encrypted (only junk-read for probing
// resistance).
func IsAEADFailureReason(reason byte) bool {
	return reason == TerminationAEADFrameError
}
