package i2np

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// EncryptShortBuildRequestRecord encrypts a BuildRequestRecord into the
// 218-byte STBM (Short Tunnel Build Message) wire format defined by the
// I2P tunnel-creation-ECIES specification (proposal 152).
//
// Wire layout (218 bytes):
//
//	[  0: 16] toPeer        - first 16 bytes of recipient identity hash
//	[ 16: 48] ephemeralKey  - sender's ephemeral X25519 public key
//	[ 48:202] ciphertext    - ChaCha20-Poly1305(zero-nonce, AD=ephemeralKey)
//	[202:218] poly1305 tag  - included in the ciphertext output above
//
// The nonce is implicitly zero because each record uses a fresh ephemeral
// key, providing per-message cryptographic uniqueness without storing a
// nonce on the wire. The associated data is the ephemeral public key,
// matching DecryptShortBuildRequestRecord in build_record_crypto.go.
//
// The shared secret is derived via X25519 then expanded with HKDF-SHA256
// using info "ECIES-X25519-AEAD" — identical to the KDF used by
// ecies.DecryptECIESX25519 — so that decryption with the recipient's
// private key yields the original cleartext.
func EncryptShortBuildRequestRecord(record BuildRequestRecord, recipientRouterInfo router_info.RouterInfo) ([218]byte, error) {
	var encrypted [218]byte

	// Serialize the full 218-byte short record. The function fills
	// [0:16] (toPeer) and the cleartext bytes at [48:202]; the ephemeral
	// key slot [16:48] and MAC slot [202:218] are left zero for us to fill.
	full := record.ShortBytes()
	if len(full) != ShortBuildRecordSize {
		return encrypted, oops.Errorf("invalid ShortBytes size: expected %d, got %d", ShortBuildRecordSize, len(full))
	}

	// Extract recipient X25519 public key from RouterInfo
	recipientPubKey, err := extractEncryptionPublicKey(recipientRouterInfo)
	if err != nil {
		return encrypted, oops.Wrapf(err, "failed to extract encryption public key")
	}

	// Generate sender's ephemeral X25519 keypair
	ephemeralPub, ephemeralPriv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return encrypted, oops.Wrapf(err, "failed to generate ephemeral X25519 keypair")
	}

	// X25519 + HKDF-SHA256("ECIES-X25519-AEAD") -> 32-byte ChaCha20-Poly1305 key
	sharedSecret, err := ephemeralPriv.SharedKey(x25519.PublicKey(recipientPubKey))
	if err != nil {
		return encrypted, oops.Wrapf(err, "X25519 key agreement failed")
	}
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ECIES-X25519-AEAD"))
	aeadKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aeadKey); err != nil {
		return encrypted, oops.Wrapf(err, "HKDF key derivation failed")
	}

	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		return encrypted, oops.Wrapf(err, "failed to create ChaCha20-Poly1305 cipher")
	}

	// STBM uses an implicit zero nonce; uniqueness is provided by the fresh
	// ephemeral key included as associated data.
	zeroNonce := make([]byte, chacha20poly1305.NonceSize)

	// Cleartext is the 154 bytes at [48:48+154] of the ShortBytes layout.
	cleartext := full[48 : 48+ShortBuildRecordCleartextLen]
	ct := aead.Seal(nil, zeroNonce, cleartext, ephemeralPub) // 154 + 16 = 170 bytes

	if len(ct) != ShortBuildRecordCleartextLen+16 {
		return encrypted, oops.Errorf("unexpected ciphertext length: got %d, want %d",
			len(ct), ShortBuildRecordCleartextLen+16)
	}

	// Assemble wire record
	copy(encrypted[0:16], full[0:16])    // toPeer prefix
	copy(encrypted[16:48], ephemeralPub) // ephemeral X25519 public key
	copy(encrypted[48:218], ct)          // ciphertext + poly1305 tag

	log.WithFields(logger.Fields{
		"at":             "EncryptShortBuildRequestRecord",
		"record_size":    ShortBuildRecordSize,
		"cleartext_size": ShortBuildRecordCleartextLen,
	}).Debug("STBM build request record encrypted successfully")

	return encrypted, nil
}
