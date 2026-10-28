// Package buildrecord defines the BuildRequestRecord type and its
// serialization/parsing logic. It is a dependency-free leaf package (no
// lib/* imports) so that both lib/tunnel and lib/i2np can import it without
// creating an import cycle.
package buildrecord

import (
	"errors"
	"strconv"
	"time"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/logger"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
)

var log = logger.GetGoI2PLogger()

// TunnelID is the uint32 type representing a tunnel identifier in the I2P network.
type TunnelID uint32

// ErrNotEnoughData is returned when a byte slice is too short for a BuildRequestRecord field.
var ErrNotEnoughData = errors.New("not enough build request record data")

// Size constants for BuildRequestRecord serialization.
const (
	// StandardCleartextLen is the cleartext size for standard/long build records (222 bytes).
	StandardCleartextLen = 222
	// ShortRecordSize is the encrypted on-wire size for short ECIES build records (218 bytes).
	ShortRecordSize = 218
	// ShortCleartextLen is the cleartext payload length for short ECIES records (154 bytes).
	ShortCleartextLen = 154
	// DefaultExpirationSeconds is the tunnel request expiration in seconds.
	// The ECIES tunnel-creation spec (tunnel-creation-ecies.rst, "Short Request
	// Record Unencrypted") states: "The request expiration is for future variable
	// tunnel duration. For now, the only supported value is 600 (10 minutes)."
	// Any other value is a protocol deviation that peers may reject. This also
	// matches the 10-minute participant lifetime used by the tunnel pool.
	DefaultExpirationSeconds = 600
)

// BuildRequestRecord contains all the data for a single tunnel hop build request.
// This is the cleartext version before encryption. It maps to the I2NP
// BuildRequestRecord structure and is the canonical definition shared between
// lib/tunnel and lib/i2np.
type BuildRequestRecord struct {
	ReceiveTunnel TunnelID
	OurIdent      common.Hash
	NextTunnel    TunnelID
	NextIdent     common.Hash
	LayerKey      session_key.SessionKey
	IVKey         session_key.SessionKey
	ReplyKey      session_key.SessionKey
	ReplyIV       [16]byte
	Flag          int
	RequestTime   time.Time
	SendMessageID int
	Padding       [29]byte

	// MinBandwidthKBps is the minimum bandwidth (KB/s) the tunnel creator
	// requires from this hop, parsed from the short build record's tunnel
	// build options mapping (key "m", i2pd TRANSIT_TUNNEL_MINIMUM_BANDWIDTH).
	// Zero means unspecified. Only populated by ReadShortBuildRequestRecord.
	MinBandwidthKBps uint32
	// RequestedBandwidthKBps is the bandwidth (KB/s) the tunnel creator
	// requests from this hop (key "r", i2pd TRANSIT_TUNNEL_REQUESTED_BANDWIDTH).
	// Zero means unspecified. Only populated by ReadShortBuildRequestRecord.
	RequestedBandwidthKBps uint32
	// LimitBandwidthKBps is the bandwidth (KB/s) limit the creator asks the
	// IBGW to apply to this tunnel (option "l"). Per
	// tunnel-creation-ecies.rst §"Build Request Options", "l" is only sent to an
	// IBGW, and the constraint is m <= r <= l. Zero means unspecified.
	LimitBandwidthKBps uint32
}

// GetReceiveTunnel returns the receive tunnel ID.
func (b *BuildRequestRecord) GetReceiveTunnel() TunnelID {
	return b.ReceiveTunnel
}

// GetNextTunnel returns the next tunnel ID.
func (b *BuildRequestRecord) GetNextTunnel() TunnelID {
	return b.NextTunnel
}

// GetOurIdent returns our identity hash.
func (b *BuildRequestRecord) GetOurIdent() common.Hash {
	return b.OurIdent
}

// GetNextIdent returns the next identity hash.
func (b *BuildRequestRecord) GetNextIdent() common.Hash {
	return b.NextIdent
}

// GetReplyKey returns the reply session key.
func (b *BuildRequestRecord) GetReplyKey() session_key.SessionKey {
	return b.ReplyKey
}

// GetLayerKey returns the layer session key.
func (b *BuildRequestRecord) GetLayerKey() session_key.SessionKey {
	return b.LayerKey
}

// GetIVKey returns the IV session key.
func (b *BuildRequestRecord) GetIVKey() session_key.SessionKey {
	return b.IVKey
}

// ShortBytes serializes the BuildRequestRecord to the 218-byte ECIES short record wire format.
//
// Layout (tunnel-creation-ecies.rst §"Short Request Record"): the first 48 bytes
// are the unencrypted prefix — toPeer hash (16) and the sender's ephemeral X25519
// key (32, zeroed here and filled during ECIES encryption) — followed by the
// 154-byte cleartext payload: tunnel IDs, next identity hash, flags, unused
// bytes, layer encryption type, request time, expiration, next message ID, the
// tunnel build options Mapping, and random padding to byte 153.
//
// The padding region must be random, not zero-filled: the spec calls it
// "random padding", and a constant tail is a fingerprint.
func (b *BuildRequestRecord) ShortBytes() []byte {
	data := make([]byte, ShortRecordSize)

	// toPeer: first 16 bytes of peer's identity hash
	copy(data[0:16], b.OurIdent[:16])
	// Ephemeral X25519 key placeholder (offset 16, 32 bytes) — zeroed, filled during ECIES encryption.
	const payloadOff = 48

	if tunnelInt, err := common.NewIntegerFromInt(int(b.ReceiveTunnel), 4); err == nil {
		copy(data[payloadOff:payloadOff+4], tunnelInt.Bytes())
	}
	if tunnelInt, err := common.NewIntegerFromInt(int(b.NextTunnel), 4); err == nil {
		copy(data[payloadOff+4:payloadOff+8], tunnelInt.Bytes())
	}
	copy(data[payloadOff+8:payloadOff+40], b.NextIdent[:])
	// flags: bit 7 IBGW, bit 6 OBEP, bits 5-0 "Undefined, must set to 0 for
	// compatibility with future options".
	data[payloadOff+40] = byte(b.Flag) & 0xC0
	// bytes 41-42: "more flags, unused, set to 0 for compatibility" (already zero)
	// layer_enc_type (1 byte) — 0 = AES (current tunnels)
	data[payloadOff+43] = 0
	minutes := int(b.RequestTime.Unix() / 60)
	if timeInt, err := common.NewIntegerFromInt(minutes, 4); err == nil {
		copy(data[payloadOff+44:payloadOff+48], timeInt.Bytes())
	}
	if expInt, err := common.NewIntegerFromInt(DefaultExpirationSeconds, 4); err == nil {
		copy(data[payloadOff+48:payloadOff+52], expInt.Bytes())
	}
	if msgInt, err := common.NewIntegerFromInt(b.SendMessageID, 4); err == nil {
		copy(data[payloadOff+52:payloadOff+56], msgInt.Bytes())
	}

	// Tunnel build options Mapping occupies payload bytes 56 onward; the spec
	// caps it at 98 bytes including its 2-byte length field. An empty Mapping is
	// the two bytes 0x00 0x00. Whatever the options do not use is random padding,
	// per "bytes x-153: random padding".
	options := b.shortBuildOptionsBytes()
	const maxOptionsLen = 98
	if len(options) > maxOptionsLen {
		log.WithFields(logger.Fields{
			"at":          "ShortBytes",
			"options_len": len(options),
			"max":         maxOptionsLen,
		}).Warn("build options too large for short record; sending empty mapping")
		options = emptyShortBuildOptions
	}
	copy(data[payloadOff+56:], options)

	paddingStart := payloadOff + 56 + len(options)
	if _, err := rand.Read(data[paddingStart : payloadOff+ShortCleartextLen]); err != nil {
		log.WithError(err).WithFields(logger.Fields{"at": "ShortBytes"}).
			Warn("failed to generate short record padding")
	}

	log.WithFields(logger.Fields{"at": "ShortBytes"}).Debug("BuildRequestRecord serialized to 218-byte short ECIES format")
	return data
}

// ReadShortBuildRequestRecord parses the 154-byte STBM cleartext payload.
//
// The Short Tunnel Build Message (STBM) cleartext is intentionally smaller
// than the long-form record. Only the following fields of the returned
// BuildRequestRecord are populated:
//   - ReceiveTunnel
//   - NextTunnel
//   - NextIdent
//   - Flag
//   - RequestTime
//   - SendMessageID
//
// All other fields (OurIdent, LayerKey, IVKey, ReplyKey, ReplyIV, ReplyTunnel,
// ReplyIdent, Padding) are left at their zero values because the short format
// does not carry them; per-hop session keys are derived elsewhere via the
// ECIES handshake. Callers MUST NOT read those fields from a record produced
// by this function.
func ReadShortBuildRequestRecord(data []byte) (BuildRequestRecord, error) {
	if len(data) < ShortCleartextLen {
		return BuildRequestRecord{}, ErrNotEnoughData
	}

	record := BuildRequestRecord{}
	record.ReceiveTunnel = TunnelID(common.Integer(data[0:4]).Int())
	record.NextTunnel = TunnelID(common.Integer(data[4:8]).Int())
	nextIdent, _, err := common.ReadHash(data[8:])
	if err != nil {
		return BuildRequestRecord{}, ErrNotEnoughData
	}
	record.NextIdent = nextIdent
	record.Flag = int(data[40])
	minutesSinceEpoch := common.Integer(data[44:48]).Int()
	record.RequestTime = time.Unix(int64(minutesSinceEpoch)*60, 0)
	record.SendMessageID = common.Integer(data[52:56]).Int()

	// Tunnel build options mapping occupies bytes [56:154] (98 bytes) in the
	// short cleartext (i2pd SHORT_REQUEST_RECORD_TUNNEL_BUILD_OPTIONS_OFFSET).
	// Parse best-effort: a malformed or empty options block leaves the
	// bandwidth fields at zero, matching i2pd's tolerant handling.
	record.MinBandwidthKBps, record.RequestedBandwidthKBps, record.LimitBandwidthKBps = parseShortBuildOptions(data[56:ShortCleartextLen])

	log.WithFields(logger.Fields{"at": "ReadShortBuildRequestRecord"}).Debug("ReadShortBuildRequestRecord: parsed 154-byte STBM cleartext")
	return record, nil
}

// Build record flag bits (tunnel-creation.rst §"Request Record Specification"):
// bit 7 IBGW, bit 6 OBEP, bits 5-0 undefined and required to be 0.
// Defined in this leaf package so both lib/tunnel and lib/i2np agree on the
// same values without either importing the other.
const (
	// FlagIBGW marks the hop as an Inbound Gateway ("allow messages from anyone").
	FlagIBGW = 0x80
	// FlagOBEP marks the hop as an Outbound Endpoint ("allow messages to anyone").
	FlagOBEP = 0x40
)

// emptyShortBuildOptions is the spec's encoding for an absent options Mapping:
// two zero bytes (a 2-byte length field of 0).
var emptyShortBuildOptions = []byte{0x00, 0x00}

// shortBuildOptionsBytes encodes the tunnel build options Mapping for this
// record: "m" (minimum bandwidth) and "r" (requested bandwidth), both KBps
// decimal strings, plus "l" (bandwidth limit) when this record is for an inbound
// gateway. Returns the empty-Mapping encoding when no options are set.
//
// Per tunnel-creation-ecies.rst §"Build Request Options", a requesting router
// may include any, all, or none of the three, under the constraint m <= r <= l.
// "l" is only meaningful to an IBGW, so it is emitted only when the IBGW flag is
// set.
func (b *BuildRequestRecord) shortBuildOptionsBytes() []byte {
	options := make(map[string]string, 3)
	if b.MinBandwidthKBps > 0 {
		options["m"] = strconv.FormatUint(uint64(b.MinBandwidthKBps), 10)
	}
	if b.RequestedBandwidthKBps > 0 {
		options["r"] = strconv.FormatUint(uint64(b.RequestedBandwidthKBps), 10)
	}
	if b.LimitBandwidthKBps > 0 && b.Flag&FlagIBGW != 0 {
		options["l"] = strconv.FormatUint(uint64(b.LimitBandwidthKBps), 10)
	}
	if len(options) == 0 {
		return emptyShortBuildOptions
	}

	mapping, err := common.GoMapToMapping(options)
	if err != nil {
		return emptyShortBuildOptions
	}
	data, err := mapping.DataSafe()
	if err != nil || len(data) == 0 {
		return emptyShortBuildOptions
	}
	return data
}

// parseShortBuildOptions extracts the transit-tunnel bandwidth options ("m" and
// "r", both decimal KB/s strings) from a short build record's options mapping.
// It is intentionally tolerant: any parse failure yields zero values, matching
// i2pd's behavior of ignoring malformed or absent build options.
func parseShortBuildOptions(optionsRegion []byte) (minKBps, requestedKBps, limitKBps uint32) {
	mapping, _, errs := common.ReadMapping(optionsRegion)
	if len(errs) != 0 {
		return 0, 0, 0
	}
	gomap, err := mapping.ToGoMap()
	if err != nil {
		return 0, 0, 0
	}
	if v, ok := gomap["m"]; ok {
		if n, perr := strconv.ParseUint(v, 10, 32); perr == nil {
			minKBps = uint32(n)
		}
	}
	if v, ok := gomap["r"]; ok {
		if n, perr := strconv.ParseUint(v, 10, 32); perr == nil {
			requestedKBps = uint32(n)
		}
	}
	// "l" is only meaningful to an IBGW, but parse it wherever it appears; the
	// caller decides whether to honour it.
	if v, ok := gomap["l"]; ok {
		if n, perr := strconv.ParseUint(v, 10, 32); perr == nil {
			limitKBps = uint32(n)
		}
	}
	return minKBps, requestedKBps, limitKBps
}
