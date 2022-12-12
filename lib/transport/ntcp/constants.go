package ntcp

import (
	"math"

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
