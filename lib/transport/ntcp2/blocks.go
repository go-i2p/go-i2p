package ntcp2

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/go-i2p/go-i2p/lib/transport"
	"time"

	"github.com/samber/oops"
)

// NTCP2 data-phase block types per the specification.
// Spec reference: https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst
// After the Noise XK handshake completes, both peers exchange AEAD-encrypted
// frames. Each decrypted frame payload consists of one or more concatenated
// blocks. Every block begins with a 3-byte header: [type:1][size:2].
const (
	// BlockTypeDateTime is a DateTime block (type 0).
	// Payload: 4 bytes, unsigned big-endian Unix epoch seconds.
	BlockTypeDateTime byte = 0

	// BlockTypeOptions is an Options block (type 1).
	// Payload: variable length, contains padding/traffic negotiation params.
	BlockTypeOptions byte = 1

	// BlockTypeRouterInfo is a RouterInfo block (type 2).
	// Payload: 1-byte flag + raw RouterInfo (never gzip-compressed in NTCP2).
	// Flag byte: bit 0 = 0 (local store) or 1 (flood request); bits 1-7 unused.
	// Spec: ntcp2.rst §1575-1577.
	BlockTypeRouterInfo byte = 2

	// BlockTypeI2NP is an I2NP message block (type 3).
	// Payload: 9-byte short I2NP header + message body.
	BlockTypeI2NP byte = 3

	// BlockTypeTermination is a Termination block (type 4).
	// Payload: valid data frames received (8 bytes, big-endian) + reason (1 byte) = 9 bytes.
	BlockTypeTermination byte = 4

	// BlockTypePadding is a Padding block (type 254).
	// Payload: arbitrary bytes, ignored by the receiver.
	BlockTypePadding byte = 254
)

// blockHeaderSize is the size of a block header: type (1 byte) + size (2 bytes).
const blockHeaderSize = 3

// MaxBlockDataSize is the largest value the 2-byte block `size` field may
// carry: ntcp2.rst:1441 "size :: 2 bytes, big endian, size of data to follow,
// 0 - 65516", restated at :1450 "Maximum single block data size is 65516
// bytes." A frame plaintext is capped at 65519 bytes (:1447 "Maximum single
// block size"), so 65516 is the most data that can follow a 3-byte header in
// one block. A larger declared size is a framing violation, not a truncation:
// it means the peer wrote a size that cannot legally exist.
const MaxBlockDataSize = 65516

// NTCP2 RouterInfo block flag byte constants (ntcp2.rst §1575-1577).
// Bit 0: 0 = local store, 1 = flood request. Bits 1-7: unused, must be 0.
// NOTE: RouterInfo in NTCP2 blocks is NEVER gzip-compressed (unlike DatabaseStore).
const (
	// RouterInfoFlagLocalStore indicates the peer should store the RouterInfo locally only.
	RouterInfoFlagLocalStore byte = 0x00
	// RouterInfoFlagFloodRequest indicates the peer should flood the RouterInfo to the netdb.
	RouterInfoFlagFloodRequest byte = 0x01
)

// Block represents a single parsed NTCP2 data-phase block. After the Noise XK
// handshake, each decrypted frame carries one or more of these blocks, which
// carry I2NP messages, RouterInfos, and control data between the two routers.
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for the block format.
// See also [ParseBlocks] and [SerializeBlocks].
type Block struct {
	// Type is the block type identifier (0–4, 254).
	Type byte

	// Data is the block payload (excluding the 3-byte header).
	Data []byte
}

// ParseBlocks parses a decrypted data-phase frame payload into individual blocks.
// The payload consists of zero or more concatenated [type:1][size:2][data:size] blocks.
// Unknown block types are preserved (returned with their raw data) so the caller
// can decide how to handle them. Returns an error if the payload is truncated.
func ParseBlocks(payload []byte) ([]Block, error) {
	var blocks []Block
	offset := 0

	for offset < len(payload) {
		// Need at least 3 bytes for the block header
		if offset+blockHeaderSize > len(payload) {
			log.WithFields(map[string]interface{}{
				"offset":    offset,
				"remaining": len(payload) - offset,
				"need":      blockHeaderSize,
			}).Error("truncated NTCP2 block header")
			return blocks, oops.Errorf("truncated block header at offset %d (have %d bytes, need %d)",
				offset, len(payload)-offset, blockHeaderSize)
		}

		blockType := payload[offset]
		blockSize := int(binary.BigEndian.Uint16(payload[offset+1 : offset+3]))
		offset += blockHeaderSize

		// ntcp2.rst:1441, :1450 bound a block's data at 65516 bytes. A larger
		// declared size is not a truncation but an illegal frame, so reject it
		// rather than trusting it for the bounds check below.
		if blockSize > MaxBlockDataSize {
			log.WithFields(map[string]interface{}{
				"block_type":    blockType,
				"declared_size": blockSize,
				"max_size":      MaxBlockDataSize,
			}).Error("NTCP2 block data size exceeds spec maximum")
			return blocks, oops.Errorf("block type %d declares %d bytes, over the %d byte maximum (ntcp2.rst:1441)",
				blockType, blockSize, MaxBlockDataSize)
		}

		if offset+blockSize > len(payload) {
			log.WithFields(map[string]interface{}{
				"block_type":    blockType,
				"declared_size": blockSize,
				"available":     len(payload) - offset,
			}).Error("truncated NTCP2 block data")
			return blocks, oops.Errorf("truncated block data at offset %d: type=%d, declared size=%d, available=%d",
				offset-blockHeaderSize, blockType, blockSize, len(payload)-offset)
		}

		data := make([]byte, blockSize)
		copy(data, payload[offset:offset+blockSize])
		blocks = append(blocks, Block{Type: blockType, Data: data})
		offset += blockSize
	}

	return blocks, nil
}

// SerializeBlocks serializes one or more blocks into a single data-phase frame
// payload suitable for writing via NTCP2Conn.Write().
func SerializeBlocks(blocks ...Block) []byte {
	// Calculate total size
	totalSize := 0
	for _, b := range blocks {
		totalSize += blockHeaderSize + len(b.Data)
	}

	payload := make([]byte, totalSize)
	offset := 0
	for _, b := range blocks {
		payload[offset] = b.Type
		binary.BigEndian.PutUint16(payload[offset+1:offset+3], uint16(len(b.Data)))
		copy(payload[offset+blockHeaderSize:], b.Data)
		offset += blockHeaderSize + len(b.Data)
	}

	return payload
}

// NewDateTimeBlock creates a DateTime block (type 0) containing the current
// Unix epoch timestamp as 4 big-endian bytes.
func NewDateTimeBlock() Block {
	data := make([]byte, 4)
	// ntcp2.rst:1491 "Implementations must round to the nearest second to
	// prevent clock bias in the network." Truncating with uint32(Unix()) is
	// always biased up to a full second into the past.
	binary.BigEndian.PutUint32(data, transport.RoundUnixSeconds(time.Now()))
	return Block{Type: BlockTypeDateTime, Data: data}
}

// ParseDateTimeBlock extracts the Unix epoch timestamp from a DateTime block's data.
// Returns an error if the data is not exactly 4 bytes.
func ParseDateTimeBlock(data []byte) (time.Time, error) {
	if len(data) != 4 {
		return time.Time{}, oops.Errorf("DateTime block data must be 4 bytes, got %d", len(data))
	}
	epoch := binary.BigEndian.Uint32(data)
	return time.Unix(int64(epoch), 0), nil
}

// NewI2NPBlock creates an I2NP message block (type 3) from raw I2NP message bytes.
// The caller is responsible for providing the short I2NP header + message body.
func NewI2NPBlock(i2npData []byte) Block {
	return Block{Type: BlockTypeI2NP, Data: i2npData}
}

// NewPaddingBlock creates a Padding block (type 254) filled with cryptographically
// random bytes. The NTCP2 spec requires random padding; zero padding is
// distinguishable from Java I2P's output and fingerprintable.
// If the CSPRNG fails (should never happen in practice), the padding falls back
// to a zero-filled slice rather than panicking.
func NewPaddingBlock(size int) Block {
	data := make([]byte, size)
	if _, err := cryptorand.Read(data); err != nil {
		// CSPRNG failure is catastrophic on any real system; log and fall back
		// to zeros rather than panicking. Callers should not reach this path.
		log.WithError(err).Error("NewPaddingBlock: CSPRNG failed, padding will be zero-filled")
	}
	return Block{Type: BlockTypePadding, Data: data}
}

// NewRouterInfoBlock creates a RouterInfo block (type 2) with a flag byte
// prepended. Per ntcp2.rst §1575-1577, the flag byte encodes:
//
//	bit 0: 0 = local store (RouterInfoFlagLocalStore), 1 = flood request (RouterInfoFlagFloodRequest)
//	bits 1-7: unused, must be 0
//
// IMPORTANT: RouterInfo in NTCP2 blocks is NEVER gzip-compressed.
// Use RouterInfoFlagLocalStore (0x00) or RouterInfoFlagFloodRequest (0x01).
func NewRouterInfoBlock(routerInfoBytes []byte, flag byte) Block {
	data := make([]byte, 1+len(routerInfoBytes))
	data[0] = flag
	copy(data[1:], routerInfoBytes)
	return Block{Type: BlockTypeRouterInfo, Data: data}
}

// BlockTypeString returns a human-readable name for a block type. It is used
// in log messages so operators can identify which block type is being handled.
// See also [Block].
func BlockTypeString(blockType byte) string {
	switch blockType {
	case BlockTypeDateTime:
		return "DateTime"
	case BlockTypeOptions:
		return "Options"
	case BlockTypeRouterInfo:
		return "RouterInfo"
	case BlockTypeI2NP:
		return "I2NP"
	case BlockTypeTermination:
		return "Termination"
	case BlockTypePadding:
		return "Padding"
	default:
		return fmt.Sprintf("Unknown(%d)", blockType)
	}
}

// OptionsData is the parsed content of an NTCP2 Options block (type 1).
//
// Spec: ntcp2.rst:1493-1542 (Options block). The block data is at least 12 bytes:
//
//	tmin(1) tmax(1) rmin(1) rmax(1) tdmy(2) rdmy(2) tdelay(2) rdelay(2)
//
// with any further bytes being "more_options", whose format the spec leaves
// TBD (:1542), so they are preserved but not interpreted.
//
// tmin/tmax/rmin/rmax are 4.4 fixed-point padding-to-data ratios: an unsigned
// 8-bit value divided by 16.0, i.e. 0 to 15.9375 (ntcp2.rst:1522-1523). They
// are the *sending* router's own limits — tmin/tmax for its transmit direction,
// rmin/rmax for the direction it receives — so a receiver applies the peer's
// tmax as the ceiling on padding it should expect inbound, and applies its own
// negotiated limits outbound.
//
// The spec hedges enforcement deliberately (:1530-1532): "These are guidelines,
// there is no enforcement. Sender should honor receiver's maximum. Sender may
// or may not honor receiver's minimum, within bandwidth constraints." Parsing
// and validating the block is therefore about correctness of the wire format,
// not about mandatory traffic behaviour.
type OptionsData struct {
	// TransmitMinRatio and TransmitMaxRatio are the sender's requested
	// transmit padding limits, as raw 4.4 fixed-point bytes.
	TransmitMinRatio byte
	TransmitMaxRatio byte
	// ReceiveMinRatio and ReceiveMaxRatio are the sender's requested receive
	// padding limits, as raw 4.4 fixed-point bytes.
	ReceiveMinRatio byte
	ReceiveMaxRatio byte
	// TransmitDummy is the max dummy traffic the sender is willing to send,
	// bytes/sec average.
	TransmitDummy uint16
	// ReceiveDummy is the dummy traffic the sender requests, bytes/sec average.
	ReceiveDummy uint16
	// TransmitDelay is the max intra-message delay the sender will insert, msec.
	TransmitDelay uint16
	// ReceiveDelay is the intra-message delay the sender requests, msec.
	ReceiveDelay uint16
	// Extra carries any "more_options" bytes past the mandatory 12. Format
	// TBD per ntcp2.rst:1542; preserved for forward compatibility.
	Extra []byte
}

// optionsDataMinSize is the mandatory Options block data size:
// 4 ratio bytes + 4 big-endian uint16 fields = 12.
// ntcp2.rst:1515 "size of options to follow, 12 bytes minimum".
const optionsDataMinSize = 12

// RatioToFloat converts a 4.4 fixed-point padding ratio byte to its float
// value, i.e. the ratio of padding to data (ntcp2.rst:1522-1528: 0x00 = no
// padding, 0x01 = 6 percent, 0x10 = 100 percent, 0x80 = 800 percent).
func RatioToFloat(b byte) float64 {
	return float64(b) / 16.0
}

// ParseOptionsBlock parses the data of an NTCP2 Options block (type 1).
// It returns an error when the block is shorter than the 12 bytes the spec
// requires (ntcp2.rst:1515), which makes the frame malformed; callers should
// treat that as a payload-format error rather than ignoring the block.
//
// There is no upstream parser to delegate to: go-noise trunk exposes only the
// unexported outbound encoders buildOptionsBlock (ntcp2/handshake.go:1139) and
// msg3Part2OptionsData (ntcp2/handshake.go:1230), and its own inbound handling
// of received options is absent, so parsing lives with the other block
// parsers in this file.
func ParseOptionsBlock(data []byte) (OptionsData, error) {
	var out OptionsData
	if len(data) < optionsDataMinSize {
		return out, oops.Errorf("NTCP2 Options block data must be at least %d bytes, got %d",
			optionsDataMinSize, len(data))
	}

	out.TransmitMinRatio = data[0]
	out.TransmitMaxRatio = data[1]
	out.ReceiveMinRatio = data[2]
	out.ReceiveMaxRatio = data[3]
	out.TransmitDummy = binary.BigEndian.Uint16(data[4:6])
	out.ReceiveDummy = binary.BigEndian.Uint16(data[6:8])
	out.TransmitDelay = binary.BigEndian.Uint16(data[8:10])
	out.ReceiveDelay = binary.BigEndian.Uint16(data[10:12])
	if len(data) > optionsDataMinSize {
		extra := make([]byte, len(data)-optionsDataMinSize)
		copy(extra, data[optionsDataMinSize:])
		out.Extra = extra
	}
	return out, nil
}
