package buildrecord

// ──────────────────────────────────────────────────────────────────────────────
// Short (ECIES) build record sizes
// ──────────────────────────────────────────────────────────────────────────────

// The short tunnel build record is 218 bytes on the wire: a 48-byte
// unencrypted prefix (toPeer hash + ephemeral X25519 key) followed by a
// 154-byte cleartext payload that is what the recipient's ECIES decryption
// yields. See tunnel-creation-ecies.rst §"Short Request Record".
// Moved from: build_request_record.go
const (
	// ShortRecordPrefixLen is the unencrypted prefix of a short build record:
	// the 16-byte toPeer hash followed by the 32-byte ephemeral public key.
	// Exported because lib/i2np encrypts and decrypts the same record and must
	// split it at the same offset.
	ShortRecordPrefixLen = 48

	// ToPeerHashLen is how many leading bytes of the next peer's identity hash
	// are written as the toPeer field. The recipient recognises the record by
	// matching this against its own hash.
	ToPeerHashLen = 16

	// EphemeralPublicKeyLen is the length of the X25519 public key carried in
	// the short record prefix. It is zeroed at serialisation time and filled in
	// during ECIES encryption.
	EphemeralPublicKeyLen = 32

	// ShortRecordTagLen is the length of the AEAD authentication tag appended
	// after the encrypted cleartext. A short record is therefore
	// prefix + cleartext + tag bytes on the wire.
	ShortRecordTagLen = 16
)

// ──────────────────────────────────────────────────────────────────────────────
// Short build record cleartext payload layout
// ──────────────────────────────────────────────────────────────────────────────

// Offsets are measured from the start of the 154-byte cleartext payload, which
// is what ReadShortBuildRequestRecord receives. When serialising, add
// ShortRecordPrefixLen to reach the corresponding absolute wire offset.
//
// Spec: tunnel-creation-ecies.rst §"Short Request Record Unencrypted"; offsets
// agree with i2pd's SHORT_REQUEST_RECORD_* constants.
// Moved from: build_request_record.go
const (
	// payloadReceiveTunnelOffset is the 4-byte receive tunnel ID.
	payloadReceiveTunnelOffset = 0
	// payloadNextTunnelOffset is the 4-byte next-hop tunnel ID.
	payloadNextTunnelOffset = 4
	// payloadNextIdentOffset is the 32-byte next-hop identity hash.
	payloadNextIdentOffset = 8
	// payloadFlagOffset is the single flags byte (bit 7 IBGW, bit 6 OBEP).
	payloadFlagOffset = 40
	// payloadLayerEncTypeOffset is the 1-byte layer encryption type. 0 means
	// AES, which is what current tunnels use.
	payloadLayerEncTypeOffset = 43
	// payloadRequestTimeOffset is the 4-byte request time, in minutes since the
	// Unix epoch.
	payloadRequestTimeOffset = 44
	// payloadExpirationOffset is the 4-byte request expiration.
	payloadExpirationOffset = 48
	// payloadSendMessageIDOffset is the 4-byte next message ID.
	payloadSendMessageIDOffset = 52
	// payloadOptionsOffset is where the tunnel build options Mapping begins, and
	// where the random padding that follows it begins.
	payloadOptionsOffset = 56

	// tunnelIDLen is the encoded width of a tunnel ID.
	tunnelIDLen = 4
	// nextIdentLen is the width of the next-hop identity hash inside the payload.
	nextIdentLen = 32

	// maxShortBuildOptionsLen caps the tunnel build options Mapping at 98 bytes
	// including its 2-byte length field: 154 - 56. An oversized Mapping is
	// replaced with the empty-Mapping encoding rather than overflowing the
	// record.
	maxShortBuildOptionsLen = ShortCleartextLen - payloadOptionsOffset

	// secondsPerMinute converts the payload's minute-resolution request time to
	// and from a Unix timestamp.
	secondsPerMinute = 60

	// shortBuildOptionCount is the number of tunnel build options a short
	// request record can carry: "m" (minimum), "r" (requested) and "l" (limit)
	// bandwidth. Used only to size the map before encoding.
	shortBuildOptionCount = 3
)

// flagBitsMask keeps only the defined flag bits (IBGW and OBEP) when writing
// the flags byte; the spec requires the remaining six bits to be zero for
// compatibility with future options.
// Moved from: build_request_record.go
const flagBitsMask = 0xC0

// ──────────────────────────────────────────────────────────────────────────────
// Long (standard) build record sizes
// ──────────────────────────────────────────────────────────────────────────────

// StandardRecordSize is the on-wire size of a deprecated long-form build
// record. Both request and response records occupy 528 bytes, which is why the
// I2NP TunnelBuild message is a fixed multiple of it.
// Moved from: build_response_record.go documentation
const StandardRecordSize = 528

// ──────────────────────────────────────────────────────────────────────────────
// Build response record layout
// ──────────────────────────────────────────────────────────────────────────────

// The cleartext long response record is a 32-byte SHA-256 hash of everything
// that follows, then random padding, then the one-byte reply code:
//
//	bytes 0-31   :: SHA-256 hash of bytes 32-527
//	bytes 32-526 :: random data
//	byte  527    :: reply
//
// Spec: i2np.rst §"Build Response Record"; tunnel-creation.rst.
// Moved from: build_response_record.go
const (
	// ResponseHashLen is the width of the leading integrity hash.
	ResponseHashLen = 32

	// responseRandomDataLen is the padding between the integrity hash and the
	// reply byte. 495 = 528 - 32 - 1.
	responseRandomDataLen = StandardRecordSize - ResponseHashLen - 1

	// responseReplyOffset is the byte holding the reply code, the last byte of
	// the record.
	responseReplyOffset = StandardRecordSize - 1
)

// ──────────────────────────────────────────────────────────────────────────────
// Legacy long-request record field widths
// ──────────────────────────────────────────────────────────────────────────────

// ReplyIVLen is the width of the per-hop reply IV in the deprecated long
// request record. The short ECIES format does not carry it; per-hop IVs are
// derived from the ECIES handshake instead. Exported because lib/tunnel
// builds the same records and must agree on the width.
// Moved from: build_request_record.go
const ReplyIVLen = 16

// LegacyPaddingLen is the width of the fixed padding tail in the deprecated
// long request record. The field is retained on BuildRequestRecord so callers
// that still read the long format see the same layout. Exported for the same
// reason as ReplyIVLen.
// Moved from: build_request_record.go
const LegacyPaddingLen = 29
