package noise

// Constants for the noise package
// Moved from: noise_constants.go, transport.go

import (
	"encoding/binary"

	"github.com/flynn/noise"
)

const (
	// NOISE_DH_CURVE25519 defines the Curve25519 Diffie-Hellman key exchange
	// Moved from: noise_constants.go
	NOISE_DH_CURVE25519 = 1

	// NOISE_CIPHER_CHACHAPOLY defines the ChaCha20-Poly1305 cipher
	// Moved from: noise_constants.go
	NOISE_CIPHER_CHACHAPOLY = 1
	// NOISE_CIPHER_AESGCM defines the AES-GCM cipher
	// Moved from: noise_constants.go
	NOISE_CIPHER_AESGCM = 2

	// NOISE_HASH_SHA256 defines the SHA256 hash function
	// Moved from: noise_constants.go
	NOISE_HASH_SHA256 = 3

	// NOISE_PATTERN_XK defines the XK handshake pattern
	// Moved from: noise_constants.go
	NOISE_PATTERN_XK = 11

	// uint16Size defines the size of a uint16 in bytes
	// Moved from: noise_constants.go
	uint16Size = 2 // uint16 takes 2 bytes

	// MaxPayloadSize defines the maximum payload size for noise packets
	// Moved from: noise_constants.go
	MaxPayloadSize = 65537

	// NOISE_PROTOCOL_NAME defines the protocol name for noise transport
	// Moved from: transport.go
	NOISE_PROTOCOL_NAME = "NOISE"
)

// ciphers maps cipher IDs to noise cipher functions
// Moved from: noise_constants.go
var ciphers = map[byte]noise.CipherFunc{
	NOISE_CIPHER_CHACHAPOLY: noise.CipherChaChaPoly,
	NOISE_CIPHER_AESGCM:     noise.CipherAESGCM,
}

// hashes maps hash IDs to noise hash functions
// Moved from: noise_constants.go
var hashes = map[byte]noise.HashFunc{
	NOISE_HASH_SHA256: noise.HashSHA256,
}

// patterns maps pattern IDs to noise handshake patterns
// Moved from: noise_constants.go
var patterns = map[byte]noise.HandshakePattern{
	NOISE_PATTERN_XK: noise.HandshakeXK,
}

// initNegotiationData initializes negotiation data with default values
// Moved from: noise_constants.go
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
