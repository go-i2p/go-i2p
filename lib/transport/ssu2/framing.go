package ssu2

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/samber/oops"
)

// FrameI2NPToBlock serializes an I2NP message into an SSU2 block type 3.
// The message is serialized with the mandatory 9-byte short I2NP header (the
// same format NTCP2 uses; SSU2 has the same format as NTCP2) and wrapped in an
// SSU2Block with BlockTypeI2NPMessage. The 16-byte standard header is never
// used on the wire here — only tunnel-delivered messages carry it.
func FrameI2NPToBlock(msg i2np.Message) (*ssu2noise.SSU2Block, error) {
	data, err := i2np.MarshalMessageShort(msg)
	if err != nil {
		log.WithError(err).Error("failed to marshal I2NP message for SSU2 block")
		return nil, oops.Wrapf(err, "failed to marshal I2NP message")
	}
	return ssu2noise.NewSSU2Block(ssu2noise.BlockTypeI2NPMessage, data), nil
}

// ParseI2NPFromBlock deserializes an SSU2 block type 3 back to an I2NP message.
// Returns an error if the block type is not BlockTypeI2NPMessage or parsing fails.
func ParseI2NPFromBlock(block *ssu2noise.SSU2Block) (i2np.Message, error) {
	if block.Type != ssu2noise.BlockTypeI2NPMessage {
		log.WithFields(map[string]interface{}{
			"expected_type": ssu2noise.BlockTypeI2NPMessage,
			"got_type":      block.Type,
		}).Error("unexpected SSU2 block type for I2NP message")
		return nil, oops.Errorf("expected block type %d (I2NP), got %d",
			ssu2noise.BlockTypeI2NPMessage, block.Type)
	}
	if len(block.Data) == 0 {
		log.Error("empty I2NP block data in SSU2 block")
		return nil, oops.Errorf("empty I2NP block data")
	}
	msg := &i2np.BaseI2NPMessage{}
	if err := msg.UnmarshalShortI2NP(block.Data); err != nil {
		log.WithError(err).Error("failed to unmarshal I2NP message from SSU2 block")
		return nil, oops.Wrapf(err, "failed to unmarshal I2NP message")
	}
	return msg, nil
}

// FrameI2NPForSSU2 serializes an I2NP message to raw bytes suitable for
// SSU2Conn.Write. This is the SSU2 equivalent of NTCP2's FrameI2NPMessage and
// uses the mandatory 9-byte short I2NP header.
func FrameI2NPForSSU2(msg i2np.Message) ([]byte, error) {
	data, err := i2np.MarshalMessageShort(msg)
	if err != nil {
		log.WithError(err).Error("failed to marshal I2NP message for SSU2")
		return nil, oops.Wrapf(err, "failed to marshal I2NP message")
	}
	return data, nil
}

// ParseI2NPFromSSU2 parses raw bytes received from SSU2Conn.Read back to
// an I2NP message. This is the SSU2 equivalent of NTCP2's UnframeI2NPMessage.
func ParseI2NPFromSSU2(data []byte) (i2np.Message, error) {
	if len(data) == 0 {
		log.Error("empty data in ParseI2NPFromSSU2")
		return nil, oops.Errorf("empty I2NP data")
	}
	msg := &i2np.BaseI2NPMessage{}
	if err := msg.UnmarshalShortI2NP(data); err != nil {
		log.WithError(err).Error("failed to unmarshal I2NP message from SSU2")
		return nil, oops.Wrapf(err, "failed to unmarshal I2NP message")
	}
	return msg, nil
}

// NewDateTimeBlock creates a DateTime block (type 0) with the current timestamp.
func NewDateTimeBlock() *ssu2noise.SSU2Block {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(time.Now().Unix()))
	return ssu2noise.NewSSU2Block(ssu2noise.BlockTypeDateTime, data)
}

// NewPaddingBlock creates a Padding block (type 254) with the given size.
func NewPaddingBlock(size int) *ssu2noise.SSU2Block {
	return ssu2noise.NewSSU2Block(ssu2noise.BlockTypePadding, make([]byte, size))
}

// ACKBlockInfo holds parsed data from an explicit ACK block (type 12).
// According to SSU2 spec section 5.2.2.1, an ACK block contains:
// - 4-byte first packet number (big-endian)
// - 1-byte nack count
// - nack count bytes of nack fields (each bit indicates nack for 8 packets)
type ACKBlockInfo struct {
	FirstPacketNum uint32   // First packet number in the ACK range
	NackCount      uint8    // Number of nack fields that follow
	NackFields     []uint8  // Bit fields: 0 = ACKed, 1 = NACKed (for 8 packets each)
	AckedRange     []uint32 // Expanded list of explicitly ACKed packet numbers
}

// ParseACKBlock parses an explicit ACK block (type 12) and extracts the acknowledged packet range.
// Returns an error if the block type is invalid or data is malformed.
//
// According to SSU2 spec 5.2.2.1, the block data contains:
// - 4 bytes: first packet number (big-endian uint32)
// - 1 byte: nack count (number of 8-bit nack fields)
// - nack count bytes: each bit indicates if a packet is NACKed (0=ACK, 1=NACK)
//
// Example: FirstPacket=100, NackCount=0 → packets 100-107 all ACKed
// Example: FirstPacket=100, NackCount=1, nack_fields=[0x05] → packets 100,102 ACKed; 101,103-107 NACKed
func ParseACKBlock(block *ssu2noise.SSU2Block) (*ACKBlockInfo, error) {
	if block.Type != ssu2noise.BlockTypeACK {
		return nil, oops.Errorf("expected ACK block (type 12), got type %d", block.Type)
	}

	if len(block.Data) < 5 {
		return nil, oops.Errorf("ACK block data too short: %d bytes (minimum 5)", len(block.Data))
	}

	info := &ACKBlockInfo{}

	// Parse first packet number (4 bytes, big-endian)
	info.FirstPacketNum = binary.BigEndian.Uint32(block.Data[0:4])

	// Parse nack count (1 byte)
	info.NackCount = block.Data[4]

	// Validate data length matches nack count
	expectedLen := 5 + int(info.NackCount)
	if len(block.Data) != expectedLen {
		return nil, oops.Errorf("ACK block data length mismatch: got %d bytes, expected %d (5 + %d nack fields)",
			len(block.Data), expectedLen, info.NackCount)
	}

	// Extract nack fields if present
	if info.NackCount > 0 {
		info.NackFields = make([]uint8, info.NackCount)
		copy(info.NackFields, block.Data[5:5+info.NackCount])
	}

	// Build expanded list of explicitly ACKed packet numbers
	// Each nack field covers 8 packets; 0 bit = ACKed, 1 bit = NACKed
	packetNum := info.FirstPacketNum
	for i, nackByte := range info.NackFields {
		_ = i // for loop iteration
		for bit := 0; bit < 8; bit++ {
			if (nackByte & (1 << uint(bit))) == 0 {
				// Bit is 0: this packet is ACKed
				info.AckedRange = append(info.AckedRange, packetNum)
			}
			// Check for uint32 wraparound before incrementing
			if packetNum == 0xFFFFFFFF {
				// Stop processing if we've reached the maximum packet number
				break
			}
			packetNum++
		}
		// Break outer loop if we hit wraparound
		if packetNum == 0xFFFFFFFF && len(info.NackFields) > i+1 {
			// NackFields remain but packet number has wrapped; stop to avoid wrapping into low numbers
			break
		}
	}

	// If no nack fields, then the first 8 packets after FirstPacketNum are all ACKed
	if info.NackCount == 0 {
		for i := 0; i < 8; i++ {
			info.AckedRange = append(info.AckedRange, info.FirstPacketNum+uint32(i))
		}
	}

	return info, nil
}
