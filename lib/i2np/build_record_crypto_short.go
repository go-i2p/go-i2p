package i2np

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/hkdf"
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
	encrypted, _, _, err := EncryptShortBuildRequestRecordWithChain(record, recipientRouterInfo)
	return encrypted, err
}

// EncryptShortBuildRequestRecordWithChain is the same as EncryptShortBuildRequestRecord
// but also returns the post-encryption Noise chaining key (32 bytes). The caller
// needs this chaining key to derive the per-hop reply/layer/IV keys via i2p HKDF
// (info="SMTunnelReplyKey" etc.) — the reply key in particular is required to
// apply the chained ChaCha20 stream-cipher layer obfuscation that the I2P tunnel
// build protocol mandates over records following each hop.
//
// See i2pd ShortECIESTunnelHopConfig::CreateBuildRequestRecord for the full
// per-hop key derivation chain. Also returns the Noise transcript hash (m_H)
// after EncryptAndHash, which the initiator stores and later uses as AEAD
// associated data when decrypting each hop's ShortTunnelBuildReply record.
func EncryptShortBuildRequestRecordWithChain(record BuildRequestRecord, recipientRouterInfo router_info.RouterInfo) ([218]byte, [32]byte, [32]byte, error) {
	var encrypted [218]byte
	var chainingKey [32]byte
	var noiseHash [32]byte

	full := record.ShortBytes()
	recipientPubKey, err := validateSTBMInputs(full, recipientRouterInfo)
	if err != nil {
		return encrypted, chainingKey, noiseHash, err
	}

	ns, ephemeralPub, err := setupNoiseProtocolForSTBM(recipientPubKey)
	if err != nil {
		return encrypted, chainingKey, noiseHash, err
	}

	cleartext := full[48 : 48+ShortBuildRecordCleartextLen]
	logSTBMEncryptionDiagnostics(record, recipientRouterInfo, recipientPubKey, cleartext)

	ct, err := ns.EncryptAndHash(nil, cleartext)
	if err != nil {
		return encrypted, chainingKey, noiseHash, oops.Wrapf(err, "Noise EncryptAndHash failed")
	}
	if len(ct) != ShortBuildRecordCleartextLen+16 {
		return encrypted, chainingKey, noiseHash, oops.Errorf("unexpected ciphertext length: got %d, want %d",
			len(ct), ShortBuildRecordCleartextLen+16)
	}

	assembleEncryptedSTBMRecord(&encrypted, full, ephemeralPub, ct)
	copy(chainingKey[:], ns.ChainingKey())
	copy(noiseHash[:], ns.HandshakeHash())

	log.WithFields(logger.Fields{
		"at":             "EncryptShortBuildRequestRecord",
		"record_size":    ShortBuildRecordSize,
		"cleartext_size": ShortBuildRecordCleartextLen,
	}).Debug("STBM build request record encrypted (Noise_N)")

	return encrypted, chainingKey, noiseHash, nil
}

// validateSTBMInputs validates the record size and extracts the recipient's encryption key.
func validateSTBMInputs(full []byte, recipientRouterInfo router_info.RouterInfo) ([]byte, error) {
	if len(full) != ShortBuildRecordSize {
		return nil, oops.Errorf("invalid ShortBytes size: expected %d, got %d", ShortBuildRecordSize, len(full))
	}

	recipientPubKey, err := extractEncryptionPublicKey(recipientRouterInfo)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to extract encryption public key")
	}
	if len(recipientPubKey) != 32 {
		return nil, oops.Errorf("invalid recipient pubkey length: %d", len(recipientPubKey))
	}

	return recipientPubKey, nil
}

// setupNoiseProtocolForSTBM initializes the Noise_N handshake and generates ephemeral keypair.
func setupNoiseProtocolForSTBM(recipientPubKey []byte) (*noise.SymmetricState, []byte, error) {
	ephemeralPub, ephemeralPriv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to generate ephemeral X25519 keypair")
	}

	ns := initSTBMNoiseN(recipientPubKey)
	ns.MixHash(ephemeralPub)

	sharedSecret, err := ephemeralPriv.SharedKey(x25519.PublicKey(recipientPubKey))
	if err != nil {
		return nil, nil, oops.Wrapf(err, "X25519 key agreement failed")
	}
	ns.MixKey(sharedSecret)

	return ns, ephemeralPub, nil
}

// logSTBMEncryptionDiagnostics logs per-record ECIES inputs for debugging.
func logSTBMEncryptionDiagnostics(record BuildRequestRecord, recipientRouterInfo router_info.RouterInfo, recipientPubKey, cleartext []byte) {
	peerHashHex := "(hash-error)"
	if ph, hErr := recipientRouterInfo.IdentHash(); hErr == nil {
		peerHashHex = logutil.HashPrefixPlain(ph)
	}
	riPublished := "(nil)"
	riAgeStr := "(nil)"
	if pub := recipientRouterInfo.Published(); pub != nil {
		pubTime := pub.Time()
		riPublished = pubTime.UTC().Format(time.RFC3339)
		riAgeStr = fmt.Sprintf("%.0fs", time.Since(pubTime).Seconds())
	}
	log.WithFields(logger.Fields{
		"at":            "EncryptShortBuildRequestRecord",
		"peer_hash":     peerHashHex,
		"enckey_hex":    logutil.BytePrefix(recipientPubKey),
		"ri_published":  riPublished,
		"ri_age":        riAgeStr,
		"record_flag":   fmt.Sprintf("0x%02x", record.Flag),
		"cleartext_hex": logutil.BytePrefix(cleartext),
	}).Warn("stbm_record_pre_encrypt")
}

// assembleEncryptedSTBMRecord copies the encrypted data into the final record layout.
func assembleEncryptedSTBMRecord(encrypted *[218]byte, full, ephemeralPub, ct []byte) {
	copy(encrypted[0:16], full[0:16])
	copy(encrypted[16:48], ephemeralPub)
	copy(encrypted[48:218], ct)
}

// DeriveSTBMReplyKey derives the per-hop ChaCha20 reply key from a hop's
// post-encryption Noise chaining key. This key is used both for the chained
// stream-cipher layer obfuscation that the sender applies to records following
// this hop, and for AEAD-decrypting that hop's build response record.
//
// The derivation matches i2pd:
//
//	HKDF-SHA256(salt=ck, ikm="", info="SMTunnelReplyKey", out=64)
//	-> new_ck (bytes 0:32) || replyKey (bytes 32:64)
//
// Returns both the replyKey and the new chaining key so callers can continue
// the HKDF chain (e.g. for layer/IV/garlic key derivation).
func DeriveSTBMReplyKey(chainingKey [32]byte) ([32]byte, [32]byte, error) {
	var replyKey, newCK [32]byte
	r := hkdf.New(sha256.New, chainingKey[:], []byte{}, []byte("SMTunnelReplyKey"))
	var out [64]byte
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return replyKey, newCK, oops.Wrapf(err, "HKDF for SMTunnelReplyKey failed")
	}
	copy(newCK[:], out[0:32])
	copy(replyKey[:], out[32:64])
	return replyKey, newCK, nil
}

// hkdf64 performs one HKDF-SHA256 step matching i2pd's HKDF(salt, nil, 0, info, out, 64):
// output is 64 bytes, [0:32]=new chaining key, [32:64]=derived key.
func hkdf64(ck [32]byte, info string) ([64]byte, error) {
	var out [64]byte
	r := hkdf.New(sha256.New, ck[:], []byte{}, []byte(info))
	_, err := io.ReadFull(r, out[:])
	return out, err
}

// DeriveSTBMOBEPGarlicKeyAndTag derives the one-time garlic key and tag that
// the OBEP uses to wrap its ShortTunnelBuildReply, matching i2pd exactly.
//
// Input: postReplyCK — the Noise chaining key after "SMTunnelReplyKey" HKDF step.
//
// Derivation (from TransitTunnel.cpp::HandleShortTransitTunnelBuildMsg):
//
//	HKDF64(postReplyCK, "SMTunnelLayerKey") -> ck1 || layerKey
//	HKDF64(ck1, "TunnelLayerIVKey")         -> ck2 || ivKey
//	HKDF64(ck2, "RGarlicKeyAndTag")          -> ck3 || garlicEncKey
//	  TAG = ck3[0:8]         (first 8 bytes of new chaining key)
//	  KEY = garlicEncKey     (output key, 32 bytes)
func DeriveSTBMOBEPGarlicKeyAndTag(postReplyCK [32]byte) ([32]byte, [8]byte, error) {
	var garlicKey [32]byte
	var tag [8]byte

	out1, err := hkdf64(postReplyCK, "SMTunnelLayerKey")
	if err != nil {
		return garlicKey, tag, oops.Wrapf(err, "HKDF for SMTunnelLayerKey failed")
	}
	var ck1 [32]byte
	copy(ck1[:], out1[0:32])

	out2, err := hkdf64(ck1, "TunnelLayerIVKey")
	if err != nil {
		return garlicKey, tag, oops.Wrapf(err, "HKDF for TunnelLayerIVKey failed")
	}
	var ck2 [32]byte
	copy(ck2[:], out2[0:32])

	out3, err := hkdf64(ck2, "RGarlicKeyAndTag")
	if err != nil {
		return garlicKey, tag, oops.Wrapf(err, "HKDF for RGarlicKeyAndTag failed")
	}
	copy(garlicKey[:], out3[32:64]) // output key
	copy(tag[:], out3[0:8])         // first 8 bytes of new chaining key (NOT output key)

	return garlicKey, tag, nil
}

// DeriveSTBMLegacyGarlicKeyFromChainingKey is retained for compatibility.
// It wraps DeriveSTBMOBEPGarlicKeyAndTag with the old name.
//
// Deprecated: use DeriveSTBMOBEPGarlicKeyAndTag directly. Will be removed in v0.2.0.
func DeriveSTBMLegacyGarlicKeyFromChainingKey(chainingKey [32]byte) ([32]byte, [8]byte, error) {
	return DeriveSTBMOBEPGarlicKeyAndTag(chainingKey)
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

// DecryptSTBMRecordReturningChainingKey performs the same Noise_N AEAD-decrypt
// as DecryptShortBuildRequestRecordNoise but returns the post-decrypt Noise
// chaining key instead of the cleartext record. This chaining key is what the
// hop needs to derive its replyKey (via DeriveSTBMReplyKey) so it can:
//
//  1. Peel its own layer off all subsequent records via ChaCha20 stream.
//  2. AEAD-decrypt the build response record addressed to it.
//
// Used by the test harness to validate the sender-side chained ChaCha20 layer
// obfuscation, and intended for use by the real receive path once we wire up
// inbound STBM handling.
func DecryptSTBMRecordReturningChainingKey(encrypted [218]byte, privateKey []byte) ([32]byte, error) {
	var chainingKey [32]byte
	if len(privateKey) != 32 {
		return chainingKey, oops.Errorf("invalid private key size: expected 32 bytes, got %d", len(privateKey))
	}
	priv := x25519.PrivateKey(privateKey)
	ourStaticPubBytes, err := priv.PublicKey()
	if err != nil {
		return chainingKey, oops.Wrapf(err, "failed to derive static public key from private key")
	}

	ephPub := encrypted[16:48]
	ct := encrypted[48:218]

	ns := initSTBMNoiseN(ourStaticPubBytes)
	ns.MixHash(ephPub)

	sharedSecret, err := priv.SharedKey(x25519.PublicKey(ephPub))
	if err != nil {
		return chainingKey, oops.Wrapf(err, "X25519 key agreement failed")
	}
	ns.MixKey(sharedSecret)

	if _, err := ns.DecryptAndHash(nil, ct); err != nil {
		return chainingKey, oops.Wrapf(err, "Noise DecryptAndHash failed")
	}
	copy(chainingKey[:], ns.ChainingKey())
	return chainingKey, nil
}

// DecryptSTBMRecordReturningChainingKeyAndHash performs the same Noise_N AEAD-decrypt
// as DecryptSTBMRecordReturningChainingKey but also returns the post-decrypt Noise
// handshake hash (m_H). The transit hop needs m_H as AEAD associated data when
// constructing its ShortTunnelBuildReply record.
func DecryptSTBMRecordReturningChainingKeyAndHash(encrypted [218]byte, privateKey []byte) ([32]byte, [32]byte, error) {
	var chainingKey [32]byte
	var noiseHash [32]byte
	if len(privateKey) != 32 {
		return chainingKey, noiseHash, oops.Errorf("invalid private key size: expected 32 bytes, got %d", len(privateKey))
	}
	priv := x25519.PrivateKey(privateKey)
	ourStaticPubBytes, err := priv.PublicKey()
	if err != nil {
		return chainingKey, noiseHash, oops.Wrapf(err, "failed to derive static public key from private key")
	}

	ephPub := encrypted[16:48]
	ct := encrypted[48:218]

	ns := initSTBMNoiseN(ourStaticPubBytes)
	ns.MixHash(ephPub)

	sharedSecret, err := priv.SharedKey(x25519.PublicKey(ephPub))
	if err != nil {
		return chainingKey, noiseHash, oops.Wrapf(err, "X25519 key agreement failed")
	}
	ns.MixKey(sharedSecret)

	if _, err := ns.DecryptAndHash(nil, ct); err != nil {
		return chainingKey, noiseHash, oops.Wrapf(err, "Noise DecryptAndHash failed")
	}
	copy(chainingKey[:], ns.ChainingKey())
	copy(noiseHash[:], ns.HandshakeHash())
	return chainingKey, noiseHash, nil
}
