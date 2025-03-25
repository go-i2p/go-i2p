package ntcp

import (
	"encoding/binary"
	"math"
	"time"

	"github.com/flynn/noise"
)

const (
	NOISE_DH_CURVE25519 = 1

	NOISE_CIPHER_CHACHAPOLY = 1
	NOISE_CIPHER_AESGCM     = 2

	NOISE_HASH_SHA256 = 3

	NOISE_PATTERN_XK = 11

	uint16Size     = 2                                             // uint16 takes 2 bytes
	MaxPayloadSize = math.MaxUint16 - 16 /*mac size*/ - uint16Size /*data len*/
)

// Constants for NTCP2 handshake
const (
	// Message 1 - SessionRequest
	NTCP2_MSG1_SIZE   = 64
	NTCP2_MSG1_HEADER = 0x00

	// Message 2 - SessionCreated
	NTCP2_MSG2_SIZE   = 64
	NTCP2_MSG2_HEADER = 0x01

	// Message 3 - SessionConfirmed
	NTCP2_MSG3_HEADER = 0x02

	// Timeout for handshake operations
	NTCP2_HANDSHAKE_TIMEOUT = 15 * time.Second
)

var ciphers = map[byte]noise.CipherFunc{
	NOISE_CIPHER_CHACHAPOLY: noise.CipherChaChaPoly,
	NOISE_CIPHER_AESGCM:     noise.CipherAESGCM,
}

var hashes = map[byte]noise.HashFunc{
	NOISE_HASH_SHA256: noise.HashSHA256,
}

var patterns = map[byte]noise.HandshakePattern{
	NOISE_PATTERN_XK: noise.HandshakeXK,
}

func initNegotiationData(negotiationData []byte) []byte {
	if negotiationData != nil {
		return negotiationData
	}
	negotiationData = make([]byte, 6)
	binary.BigEndian.PutUint16(negotiationData, 1) // version
	negotiationData[2] = NOISE_DH_CURVE25519
	negotiationData[3] = NOISE_CIPHER_CHACHAPOLY
	negotiationData[4] = NOISE_HASH_SHA256
	return negotiationData
}
