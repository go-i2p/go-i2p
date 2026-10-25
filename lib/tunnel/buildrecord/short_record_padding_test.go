package buildrecord

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baseShortRecord returns a BuildRequestRecord with the fields that affect the
// short-record wire layout populated deterministically.
func baseShortRecord() BuildRequestRecord {
	var ident [32]byte
	for i := range ident {
		ident[i] = byte(i + 1)
	}
	return BuildRequestRecord{
		ReceiveTunnel: TunnelID(0x01020304),
		NextTunnel:    TunnelID(0x05060708),
		OurIdent:      ident,
		NextIdent:     ident,
		Flag:          FlagIBGW,
		RequestTime:   time.Unix(60*5000, 0),
		SendMessageID: 0x0A0B0C0D,
	}
}

// TestShortBytes_PaddingIsRandom verifies the tail of the short request record
// is random padding, not zeros. tunnel-creation-ecies.rst §"Short Request Record
// Unencrypted" specifies "bytes x-153: random padding"; a zero-filled tail is a
// fingerprint that identifies the implementation.
func TestShortBytes_PaddingIsRandom(t *testing.T) {
	record := baseShortRecord()
	data := record.ShortBytes()
	require.Len(t, data, ShortRecordSize)

	const payloadOff = 48
	// Options are absent here (empty mapping = 2 zero bytes at payload[56:58]),
	// so padding begins at payload offset 58 and runs to the end of the 154-byte
	// cleartext.
	padding := data[payloadOff+58 : payloadOff+ShortCleartextLen]
	require.NotEmpty(t, padding)

	nonZero := 0
	for _, b := range padding {
		if b != 0 {
			nonZero++
		}
	}
	assert.Greater(t, nonZero, len(padding)/2,
		"padding region must be random, not zero-filled")

	// Two serializations must differ (randomness, not a fixed pattern).
	other := baseShortRecord()
	otherData := other.ShortBytes()
	assert.NotEqual(t, padding, otherData[payloadOff+58:payloadOff+ShortCleartextLen],
		"padding must be freshly random per record")
}

// TestShortBytes_EmptyOptionsMapping verifies the empty options Mapping is the
// spec's two zero bytes at payload offset 56.
func TestShortBytes_EmptyOptionsMapping(t *testing.T) {
	record := baseShortRecord()
	data := record.ShortBytes()

	const payloadOff = 48
	assert.Equal(t, byte(0), data[payloadOff+56], "empty mapping high length byte")
	assert.Equal(t, byte(0), data[payloadOff+57], "empty mapping low length byte")
}

// TestShortBytes_UndefinedFlagBitsAreZero verifies bits 5-0 of the flags byte are
// written as 0. The spec: "bits 5-0: Undefined, must set to 0 for compatibility
// with future options."
func TestShortBytes_UndefinedFlagBitsAreZero(t *testing.T) {
	record := baseShortRecord()
	record.Flag = FlagIBGW | 0x3F // set every undefined bit
	data := record.ShortBytes()

	const payloadOff = 48
	assert.Equal(t, byte(FlagIBGW), data[payloadOff+40],
		"only bit 7 (IBGW) survives; undefined bits must serialize as 0")
}

// TestShortBytes_OptionsMappingRoundTrip verifies m/r/l options are serialized
// into the options Mapping and can be parsed back by the record parser.
func TestShortBytes_OptionsMappingRoundTrip(t *testing.T) {
	record := baseShortRecord()
	record.MinBandwidthKBps = 100
	record.RequestedBandwidthKBps = 200
	record.LimitBandwidthKBps = 300 // only sent to an IBGW; record.Flag is IBGW

	data := record.ShortBytes()
	const payloadOff = 48

	// Mapping length field must be non-zero now that options are present.
	mappingLen := int(data[payloadOff+56])<<8 | int(data[payloadOff+57])
	require.Greater(t, mappingLen, 0, "options mapping must be written")

	parsed, err := ReadShortBuildRequestRecord(data[payloadOff:])
	require.NoError(t, err)
	assert.Equal(t, uint32(100), parsed.MinBandwidthKBps, "m option round-trips")
	assert.Equal(t, uint32(200), parsed.RequestedBandwidthKBps, "r option round-trips")
}

// TestShortBytes_LimitOptionOnlyForIBGW verifies "l" is emitted only when the
// record is addressed to an inbound gateway, per "l := limit bandwidth for this
// tunnel; only sent to IBGW".
func TestShortBytes_LimitOptionOnlyForIBGW(t *testing.T) {
	const payloadOff = 48

	nonGateway := baseShortRecord()
	nonGateway.Flag = 0 // intermediate participant
	nonGateway.LimitBandwidthKBps = 500
	data := nonGateway.ShortBytes()
	assert.Equal(t, byte(0), data[payloadOff+56],
		"l must not be sent to a non-IBGW hop")

	gateway := baseShortRecord()
	gateway.Flag = FlagIBGW
	gateway.LimitBandwidthKBps = 500
	gwData := gateway.ShortBytes()
	gwMappingLen := int(gwData[payloadOff+56])<<8 | int(gwData[payloadOff+57])
	assert.Greater(t, gwMappingLen, 0, "l must be sent to the IBGW")
}
