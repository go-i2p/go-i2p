package ssu2

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
)

// FrameI2NPToBlock serializes an I2NP message into an SSU2 block type 3.
// The message is serialized using its standard binary format and wrapped
// in an SSU2Block with BlockTypeI2NPMessage.
func FrameI2NPToBlock(msg i2np.I2NPMessage) (*ssu2noise.SSU2Block, error) {
	data, err := msg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal I2NP message: %w", err)
	}
	return ssu2noise.NewSSU2Block(ssu2noise.BlockTypeI2NPMessage, data), nil
}

// ParseI2NPFromBlock deserializes an SSU2 block type 3 back to an I2NP message.
// Returns an error if the block type is not BlockTypeI2NPMessage or parsing fails.
func ParseI2NPFromBlock(block *ssu2noise.SSU2Block) (i2np.I2NPMessage, error) {
	if block.Type != ssu2noise.BlockTypeI2NPMessage {
		return nil, fmt.Errorf("expected block type %d (I2NP), got %d",
			ssu2noise.BlockTypeI2NPMessage, block.Type)
	}
	if len(block.Data) == 0 {
		return nil, fmt.Errorf("empty I2NP block data")
	}
	msg := &i2np.BaseI2NPMessage{}
	if err := msg.UnmarshalBinary(block.Data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal I2NP message: %w", err)
	}
	return msg, nil
}

// FrameI2NPForSSU2 serializes an I2NP message to raw bytes suitable for
// SSU2Conn.Write. This is the SSU2 equivalent of NTCP2's FrameI2NPMessage.
func FrameI2NPForSSU2(msg i2np.I2NPMessage) ([]byte, error) {
	data, err := msg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal I2NP message: %w", err)
	}
	return data, nil
}

// ParseI2NPFromSSU2 parses raw bytes received from SSU2Conn.Read back to
// an I2NP message. This is the SSU2 equivalent of NTCP2's UnframeI2NPMessage.
func ParseI2NPFromSSU2(data []byte) (i2np.I2NPMessage, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty I2NP data")
	}
	msg := &i2np.BaseI2NPMessage{}
	if err := msg.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal I2NP message: %w", err)
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
