package ssu2

import (
	"encoding/binary"
	"fmt"

	"github.com/go-i2p/go-i2p/lib/i2np"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
)

// maxSSU2PayloadIPv4 is the maximum payload per SSU2 packet for IPv4.
// 1472 (max packet) - 16 (short header) - 16 (MAC) = 1440 bytes available.
const maxSSU2PayloadIPv4 = 1440

// maxSSU2PayloadIPv6 is the maximum payload per SSU2 packet for IPv6.
// 1452 (max packet) - 16 (short header) - 16 (MAC) = 1420 bytes available.
const maxSSU2PayloadIPv6 = 1420

// fragmentHeaderSize is the overhead per fragment block header.
// TLV header (3 bytes) + MessageID (4 bytes) = 7 bytes minimum.
// FirstFragment adds TotalSize (4 bytes) = 11 bytes total.
// FollowOnFragment adds FragmentNum (1 byte) = 8 bytes total.
const (
	firstFragmentOverhead    = 3 + 4 + 4 // TLV header + messageID + totalSize
	followOnFragmentOverhead = 3 + 4 + 1 // TLV header + messageID + fragmentNum
)

// FragmentI2NPMessage splits a large I2NP message into SSU2 fragment blocks
// when the serialized message exceeds the MTU. Returns a single-element slice
// containing a type 3 (I2NPMessage) block when no fragmentation is needed.
func FragmentI2NPMessage(msg i2np.I2NPMessage, maxPayload int) ([]*ssu2noise.SSU2Block, error) {
	data, err := msg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal I2NP message: %w", err)
	}

	blockOverhead := 3 // TLV header for type 3 block
	if len(data)+blockOverhead <= maxPayload {
		return []*ssu2noise.SSU2Block{
			ssu2noise.NewSSU2Block(ssu2noise.BlockTypeI2NPMessage, data),
		}, nil
	}

	return fragmentData(data, uint32(msg.MessageID()), maxPayload)
}

// fragmentData splits raw message data into FirstFragment + FollowOnFragment blocks.
func fragmentData(data []byte, messageID uint32, maxPayload int) ([]*ssu2noise.SSU2Block, error) {
	totalSize := uint32(len(data))
	var blocks []*ssu2noise.SSU2Block

	// First fragment
	firstDataSize := maxPayload - firstFragmentOverhead
	if firstDataSize <= 0 {
		return nil, fmt.Errorf("max payload %d too small for first fragment", maxPayload)
	}
	if firstDataSize > len(data) {
		firstDataSize = len(data)
	}

	firstBlock := buildFirstFragment(messageID, totalSize, data[:firstDataSize])
	blocks = append(blocks, firstBlock)

	offset := firstDataSize
	fragmentNum := uint8(1)

	for offset < len(data) {
		followDataSize := maxPayload - followOnFragmentOverhead
		if followDataSize <= 0 {
			return nil, fmt.Errorf("max payload %d too small for follow-on fragment", maxPayload)
		}
		end := offset + followDataSize
		if end > len(data) {
			end = len(data)
		}

		followBlock := buildFollowOnFragment(messageID, fragmentNum, data[offset:end])
		blocks = append(blocks, followBlock)

		offset = end
		fragmentNum++
		if fragmentNum == 0 {
			return nil, fmt.Errorf("message too large: exceeds 255 fragments")
		}
	}

	return blocks, nil
}

// buildFirstFragment creates a BlockTypeFirstFragment (type 4) block.
// Format: MessageID(4) + TotalSize(4) + Data(variable)
func buildFirstFragment(messageID, totalSize uint32, data []byte) *ssu2noise.SSU2Block {
	payload := make([]byte, 8+len(data))
	binary.BigEndian.PutUint32(payload[0:4], messageID)
	binary.BigEndian.PutUint32(payload[4:8], totalSize)
	copy(payload[8:], data)
	return ssu2noise.NewSSU2Block(ssu2noise.BlockTypeFirstFragment, payload)
}

// buildFollowOnFragment creates a BlockTypeFollowOnFragment (type 5) block.
// Format: MessageID(4) + FragmentNum(1) + Data(variable)
func buildFollowOnFragment(messageID uint32, fragmentNum uint8, data []byte) *ssu2noise.SSU2Block {
	payload := make([]byte, 5+len(data))
	binary.BigEndian.PutUint32(payload[0:4], messageID)
	payload[4] = fragmentNum
	copy(payload[5:], data)
	return ssu2noise.NewSSU2Block(ssu2noise.BlockTypeFollowOnFragment, payload)
}
