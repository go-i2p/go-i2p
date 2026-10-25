package i2np

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/go-i2p/common/router_info"
	i2ptunnel "github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
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
	}).Debug("stbm_record_pre_encrypt") // C2 FIX: Changed from Warn() to Debug() to protect anonymity
}

// assembleEncryptedSTBMRecord copies the encrypted data into the final record layout.
func assembleEncryptedSTBMRecord(encrypted *[218]byte, full, ephemeralPub, ct []byte) {
	copy(encrypted[0:16], full[0:16])
	copy(encrypted[16:48], ephemeralPub)
	copy(encrypted[48:218], ct)
}

// STBM reply/layer/IV key derivation.
//
// Delegates to the canonical implementation in github.com/go-i2p/crypto/tunnel
// (DeriveBuildReplyKeysFromChain), which is pinned by known-answer tests there.
// Keeping one implementation matters because the spec's KDF is DIFFERENT for
// the outbound endpoint (OBEP) and every other hop (tunnel-creation-ecies.rst
// "Reply keys"):
//
//   keydata = HKDF(ck, ZEROLEN, "SMTunnelReplyKey", 64)
//     replyKey = keydata[32:63]; ck = keydata[0:31]
//   keydata = HKDF(ck, ZEROLEN, "SMTunnelLayerKey", 64)
//     layerKey = keydata[32:63]
//     non-OBEP: ivKey = keydata[0:31]              ("because it's last")
//     OBEP:     ck = keydata[0:31]
//               keydata = HKDF(ck, ZEROLEN, "TunnelLayerIVKey", 64)
//               ivKey = keydata[32:63]; ck = keydata[0:31]
//               keydata = HKDF(ck, ZEROLEN, "RGarlicKeyAndTag", 64)
//               garlicReplyKey = keydata[32:63]; garlicReplyTag = keydata[0:7]
//
// Note: "The KDF for the IV key at the OBEP is different from that for the
// other hops, even if the reply is not garlic encrypted." A single chain that
// always runs TunnelLayerIVKey gives transit hops an IV key the tunnel creator
// never used (and vice versa), so tunnel data cannot be decrypted at the peer.
//
// Callers pass the PRE-reply chaining key: the Noise ck immediately after the
// hop's request record was encrypted/decrypted, before any reply KDF step.

// deriveSTBMHopKeys runs the upstream reply/layer/IV (and OBEP garlic) KDF for
// one hop. isOBEP must come from the hop's build request record Flag bit 6.
func deriveSTBMHopKeys(preReplyCK [32]byte, isOBEP bool) (i2ptunnel.BuildReplyKeys, error) {
	return i2ptunnel.DeriveBuildReplyKeysFromChain(preReplyCK, isOBEP)
}

// decryptSTBMRecord performs the Noise_N AEAD-decrypt of a 218-byte STBM build
// request record and returns everything a transit hop needs:
//
//   - the parsed cleartext BuildRequestRecord (whose Flag carries the OBEP bit
//     the reply/layer KDF branch depends on)
//   - the PRE-reply chaining key (ck right after the request record, before any
//     reply KDF step) - feed this to deriveSTBMHopKeys with the hop's isOBEP
//   - the post-decrypt handshake hash m_H, used as AEAD associated data when the
//     hop builds its own ShortTunnelBuildReply record
//
// The transcript is the inverse of EncryptShortBuildRequestRecordWithChain:
//
//	state = NewNoiseN(our_static_pub)   // MixHash(protocol), MixHash(""), MixHash(rs)
//	MixHash(eph_pub)
//	MixKey(X25519(our_static_priv, eph_pub))
//	cleartext = AEAD_ChaCha20Poly1305(key=k, nonce=0, ad=h).Open(ct)
//	MixHash(ct)
func decryptSTBMRecord(encrypted [218]byte, privateKey []byte) (BuildRequestRecord, [32]byte, [32]byte, error) {
	var chainingKey, noiseHash [32]byte
	if len(privateKey) != 32 {
		return BuildRequestRecord{}, chainingKey, noiseHash, oops.Errorf("invalid private key size: expected 32 bytes, got %d", len(privateKey))
	}

	// Recover our static public key by performing X25519(priv, basepoint). We
	// need it to seed the Noise_N initial state with rs = our static pub.
	priv := x25519.PrivateKey(privateKey)
	ourStaticPubBytes, err := priv.PublicKey()
	if err != nil {
		return BuildRequestRecord{}, chainingKey, noiseHash, oops.Wrapf(err, "failed to derive static public key from private key")
	}

	ephPub := encrypted[16:48]
	ct := encrypted[48:218] // 154 bytes plaintext + 16 byte tag

	ns := initSTBMNoiseN(ourStaticPubBytes)
	ns.MixHash(ephPub)

	sharedSecret, err := priv.SharedKey(x25519.PublicKey(ephPub))
	if err != nil {
		return BuildRequestRecord{}, chainingKey, noiseHash, oops.Wrapf(err, "X25519 key agreement failed")
	}
	ns.MixKey(sharedSecret)

	cleartext, err := ns.DecryptAndHash(nil, ct)
	if err != nil {
		return BuildRequestRecord{}, chainingKey, noiseHash, oops.Wrapf(err, "Noise DecryptAndHash failed")
	}
	if len(cleartext) != ShortBuildRecordCleartextLen {
		return BuildRequestRecord{}, chainingKey, noiseHash, oops.Errorf("unexpected cleartext length: got %d, want %d",
			len(cleartext), ShortBuildRecordCleartextLen)
	}

	copy(chainingKey[:], ns.ChainingKey())
	copy(noiseHash[:], ns.HandshakeHash())

	record, err := ReadShortBuildRequestRecord(cleartext)
	if err != nil {
		return BuildRequestRecord{}, chainingKey, noiseHash, err
	}
	return record, chainingKey, noiseHash, nil
}

// extractEncryptionPublicKey retrieves the X25519 public encryption key from a
// RouterInfo. Used by the short-record build-request encryption path.
func extractEncryptionPublicKey(routerInfo router_info.RouterInfo) ([]byte, error) {
	identity := routerInfo.RouterIdentity()
	if identity == nil {
		return nil, oops.Errorf("RouterInfo has nil RouterIdentity")
	}

	keysAndCert := identity.KeysAndCert
	if keysAndCert == nil {
		return nil, oops.Errorf("RouterIdentity has nil KeysAndCert")
	}

	pubKey, err := keysAndCert.PublicKey()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get PublicKey from KeysAndCert")
	}
	if pubKey == nil {
		return nil, oops.Errorf("KeysAndCert has nil PublicKey")
	}

	pubKeyBytes := pubKey.Bytes()
	if len(pubKeyBytes) != 32 {
		return nil, oops.Errorf("invalid public key size: expected 32 bytes (X25519), got %d", len(pubKeyBytes))
	}

	return pubKeyBytes, nil
}

// DecryptShortBuildRequestRecord decrypts a 218-byte STBM (Short Tunnel Build
// Message) record and returns only the parsed cleartext record. See
// decryptSTBMRecord for the full Noise_N_25519_ChaChaPoly_SHA256 transcript.
//
// STBM on-wire layout (218 bytes):
//   - Bytes   0-15:  toPeer (first 16 bytes of recipient identity hash)
//   - Bytes  16-47:  sender ephemeral X25519 public key
//   - Bytes  48-201: ChaCha20-Poly1305 ciphertext (154 bytes of cleartext)
//   - Bytes 202-217: Poly1305 MAC tag (16 bytes)
func DecryptShortBuildRequestRecord(encrypted [218]byte, privateKey []byte) (BuildRequestRecord, error) {
	record, _, _, err := decryptSTBMRecord(encrypted, privateKey)
	return record, err
}
