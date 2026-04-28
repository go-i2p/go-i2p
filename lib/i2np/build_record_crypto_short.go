package i2np

import (
	"crypto/rand"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
)

// stbmNoiseProtocolName is the Noise protocol name used by Java I2P and i2pd
// for the Short Tunnel Build Message (proposal 152). It selects Noise_N
// (one-way, known recipient static key) with X25519, ChaCha20-Poly1305, SHA256.
//
// At 31 bytes (≤ HASHLEN=32) the standard Noise InitializeSymmetric rule
// pads it with a single zero byte to form h and ck.
const stbmNoiseProtocolName = "Noise_N_25519_ChaChaPoly_SHA256"

// initSTBMNoiseN constructs the initial Noise_N symmetric state for an STBM
// record encrypted to the given recipient static X25519 public key. The
// transcript matches i2pd's InitNoiseNState followed by the receive-static
// pre-message MixHash:
//
//	h  = padded(protocol_name, 32)
//	ck = padded(protocol_name, 32)
//	h  = SHA256(h || "")              MixHash(empty prologue)
//	h  = SHA256(h || recipient_static) MixHash(rs)
//
// The empty-prologue MixHash is required to match the i2pd transcript: their
// precomputed hh = SHA256(protocol_name || 0) implicitly bakes that step in.
func initSTBMNoiseN(recipientStaticPub []byte) *noise.SymmetricState {
	ns := &noise.SymmetricState{}
	ns.SetCipherSuite(noise.ChaChaPoly_SHA256())
	ns.InitializeSymmetric([]byte(stbmNoiseProtocolName))
	ns.MixHash([]byte{}) // empty prologue, per Noise spec §5.6
	ns.MixHash(recipientStaticPub)
	return ns
}

// EncryptShortBuildRequestRecord encrypts a BuildRequestRecord into the
// 218-byte STBM (Short Tunnel Build Message) wire format defined by the
// I2P tunnel-creation-ECIES specification (proposal 152).
//
// Wire layout (218 bytes):
//
//	[  0: 16] toPeer        - first 16 bytes of recipient identity hash
//	[ 16: 48] ephemeralKey  - sender's ephemeral X25519 public key
//	[ 48:202] ciphertext    - ChaCha20-Poly1305(key=k, nonce=0, AD=h)
//	[202:218] poly1305 tag  - included in the ciphertext output above
//
// The crypto follows the Noise_N_25519_ChaChaPoly_SHA256 pattern with the
// sender as the initiator and the hop's static key as the responder static.
// Per i2pd's CreateBuildRequestRecord / RouterContext::DecryptECIESTunnelBuildRecord
// the per-record transcript is:
//
//	state = InitNoiseN(recipient_static_pub)
//	MixHash(eph_pub)
//	MixKey(X25519(eph_priv, recipient_static))
//	ciphertext = AEAD_ChaCha20Poly1305(key=ck[32:64], nonce=0, ad=h, plaintext)
//	MixHash(ciphertext)
func EncryptShortBuildRequestRecord(record BuildRequestRecord, recipientRouterInfo router_info.RouterInfo) ([218]byte, error) {
	var encrypted [218]byte

	// Serialize the full 218-byte short record. ShortBytes fills [0:16]
	// (toPeer) and the cleartext bytes at [48:48+154]; the ephemeral key
	// slot [16:48] and AEAD tag slot [202:218] are left zero for us.
	full := record.ShortBytes()
	if len(full) != ShortBuildRecordSize {
		return encrypted, oops.Errorf("invalid ShortBytes size: expected %d, got %d", ShortBuildRecordSize, len(full))
	}

	// Extract recipient X25519 static public key from RouterInfo.
	recipientPubKey, err := extractEncryptionPublicKey(recipientRouterInfo)
	if err != nil {
		return encrypted, oops.Wrapf(err, "failed to extract encryption public key")
	}
	if len(recipientPubKey) != 32 {
		return encrypted, oops.Errorf("invalid recipient pubkey length: %d", len(recipientPubKey))
	}

	// Generate sender's ephemeral X25519 keypair.
	ephemeralPub, ephemeralPriv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return encrypted, oops.Wrapf(err, "failed to generate ephemeral X25519 keypair")
	}

	// Build the Noise_N symmetric state for this hop and step the transcript:
	//   state = InitNoiseN(rs)
	//   MixHash(eph_pub)
	//   MixKey(X25519(eph_priv, rs))
	ns := initSTBMNoiseN(recipientPubKey)
	ns.MixHash(ephemeralPub)

	sharedSecret, err := ephemeralPriv.SharedKey(x25519.PublicKey(recipientPubKey))
	if err != nil {
		return encrypted, oops.Wrapf(err, "X25519 key agreement failed")
	}
	ns.MixKey(sharedSecret)

	// EncryptAndHash performs:
	//   ct = AEAD(k, nonce=0, ad=h, plaintext)
	//   MixHash(ct)
	// matching i2pd's EncryptECIES in TunnelConfig.cpp.
	cleartext := full[48 : 48+ShortBuildRecordCleartextLen]
	ct, err := ns.EncryptAndHash(nil, cleartext)
	if err != nil {
		return encrypted, oops.Wrapf(err, "Noise EncryptAndHash failed")
	}
	if len(ct) != ShortBuildRecordCleartextLen+16 {
		return encrypted, oops.Errorf("unexpected ciphertext length: got %d, want %d",
			len(ct), ShortBuildRecordCleartextLen+16)
	}

	// Assemble the wire record.
	copy(encrypted[0:16], full[0:16])    // toPeer prefix
	copy(encrypted[16:48], ephemeralPub) // sender ephemeral X25519 public key
	copy(encrypted[48:218], ct)          // ciphertext + Poly1305 tag

	log.WithFields(logger.Fields{
		"at":             "EncryptShortBuildRequestRecord",
		"record_size":    ShortBuildRecordSize,
		"cleartext_size": ShortBuildRecordCleartextLen,
	}).Debug("STBM build request record encrypted (Noise_N)")

	return encrypted, nil
}

// DecryptShortBuildRequestRecordNoise is the inverse of EncryptShortBuildRequestRecord:
// it decrypts a 218-byte STBM record using the Noise_N_25519_ChaChaPoly_SHA256
// transcript described above. The caller supplies the local router's static
// X25519 private key (which corresponds to the public key the sender used as
// the responder static).
//
// Returns the parsed cleartext BuildRequestRecord on success.
func DecryptShortBuildRequestRecordNoise(encrypted [218]byte, privateKey []byte) (BuildRequestRecord, error) {
	if len(privateKey) != 32 {
		return BuildRequestRecord{}, oops.Errorf("invalid private key size: expected 32 bytes, got %d", len(privateKey))
	}

	// Recover our static public key by performing X25519(priv, basepoint).
	// We need it to seed the Noise_N initial state with rs = our static pub.
	priv := x25519.PrivateKey(privateKey)
	ourStaticPubBytes, err := priv.PublicKey()
	if err != nil {
		return BuildRequestRecord{}, oops.Wrapf(err, "failed to derive static public key from private key")
	}

	ephPub := encrypted[16:48]
	ct := encrypted[48:218] // 154 bytes plaintext + 16 byte tag

	ns := initSTBMNoiseN(ourStaticPubBytes)
	ns.MixHash(ephPub)

	sharedSecret, err := priv.SharedKey(x25519.PublicKey(ephPub))
	if err != nil {
		return BuildRequestRecord{}, oops.Wrapf(err, "X25519 key agreement failed")
	}
	ns.MixKey(sharedSecret)

	cleartext, err := ns.DecryptAndHash(nil, ct)
	if err != nil {
		return BuildRequestRecord{}, oops.Wrapf(err, "Noise DecryptAndHash failed")
	}
	if len(cleartext) != ShortBuildRecordCleartextLen {
		return BuildRequestRecord{}, oops.Errorf("unexpected cleartext length: got %d, want %d",
			len(cleartext), ShortBuildRecordCleartextLen)
	}

	log.WithField("cleartext_size", ShortBuildRecordCleartextLen).
		Debug("STBM build request record decrypted (Noise_N)")
	return ReadShortBuildRequestRecord(cleartext)
}
