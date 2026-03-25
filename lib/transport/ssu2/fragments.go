package ssu2

import (
	"encoding/binary"
	"fmt"

	"github.com/go-i2p/go-i2p/lib/i2np"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
)

// maxSSU2PayloadIPv4 is the maximum plaintext payload per SSU2 packet for IPv4.
// 1472 (max wire) - 16 (short header) - 16 (MAC placeholder) - 16 (AEAD tag) = 1424 bytes.
const maxSSU2PayloadIPv4 = 1424

// maxSSU2PayloadIPv6 is the maximum plaintext payload per SSU2 packet for IPv6.
// 1452 (max wire) - 16 (short header) - 16 (MAC placeholder) - 16 (AEAD tag) = 1404 bytes.
const maxSSU2PayloadIPv6 = 1404

// Fragment block overhead per SSU2 spec.
// Both block types carry a 7-byte header inside the TLV payload:
//
//	FirstFragment:    MessageID(4) + FragInfo(1) + TotalSize uint16(2)
//	FollowOnFragment: FragInfo(1)  + Reserved(2) + MessageID(4)
//
// Plus the 3-byte TLV wrapper (type + 2-byte length) = 10 bytes total each.
const (
	firstFragmentOverhead    = 3 + 7 // TLV header + spec-defined fragment header
	followOnFragmentOverhead = 3 + 7 // TLV header + spec-defined fragment header
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

	firstBlock, firstDataSize, err := createFirstFragment(data, messageID, totalSize, maxPayload)
	if err != nil {
		return nil, err
	}
	blocks = append(blocks, firstBlock)

	if firstDataSize < len(data) {
		followBlocks, err := createFollowOnFragments(data[firstDataSize:], messageID, maxPayload)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, followBlocks...)
	}

	return blocks, nil
}

// createFirstFragment creates the first fragment block.
func createFirstFragment(data []byte, messageID, totalSize uint32, maxPayload int) (*ssu2noise.SSU2Block, int, error) {
	firstDataSize := maxPayload - firstFragmentOverhead
	if firstDataSize <= 0 {
		return nil, 0, fmt.Errorf("max payload %d too small for first fragment", maxPayload)
	}
	if firstDataSize > len(data) {
		firstDataSize = len(data)
	}
	isLast := firstDataSize == len(data)
	block := buildFirstFragment(messageID, totalSize, data[:firstDataSize], isLast)
	return block, firstDataSize, nil
}

// createFollowOnFragments creates all follow-on fragment blocks for remaining data.
func createFollowOnFragments(data []byte, messageID uint32, maxPayload int) ([]*ssu2noise.SSU2Block, error) {
	var blocks []*ssu2noise.SSU2Block
	offset := 0
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

		isLast := end == len(data)
		block := buildFollowOnFragment(messageID, fragmentNum, data[offset:end], isLast)
		blocks = append(blocks, block)

		offset = end
		fragmentNum++
		if fragmentNum > 127 {
			return nil, fmt.Errorf("message too large: exceeds 127 follow-on fragments")
		}
	}

	return blocks, nil
}

// buildFirstFragment creates a BlockTypeFirstFragment (type 4) block.
// SSU2 spec format: MessageID(4) + FragInfo(1) + TotalSize uint16(2) + Data
// FragInfo = (0 << 1) | isLast  (fragment number 0, isLast flag in bit 0).
func buildFirstFragment(messageID, totalSize uint32, data []byte, isLast bool) *ssu2noise.SSU2Block {
	payload := make([]byte, 7+len(data))
	binary.BigEndian.PutUint32(payload[0:4], messageID)
	isLastBit := uint8(0)
	if isLast {
		isLastBit = 1
	}
	payload[4] = isLastBit // fragNum=0 for first fragment; isLast in bit 0
	binary.BigEndian.PutUint16(payload[5:7], uint16(totalSize))
	copy(payload[7:], data)
	return ssu2noise.NewSSU2Block(ssu2noise.BlockTypeFirstFragment, payload)
}

// buildFollowOnFragment creates a BlockTypeFollowOnFragment (type 5) block.
// SSU2 spec format: FragInfo(1) + Reserved(2) + MessageID(4) + Data
// FragInfo = (fragmentNum << 1) | isLast  (fragment number in bits 7:1, isLast in bit 0).
func buildFollowOnFragment(messageID uint32, fragmentNum uint8, data []byte, isLast bool) *ssu2noise.SSU2Block {
	payload := make([]byte, 7+len(data))
	isLastBit := uint8(0)
	if isLast {
		isLastBit = 1
	}
	payload[0] = (fragmentNum << 1) | isLastBit
	payload[1] = 0 // reserved
	payload[2] = 0 // reserved
	binary.BigEndian.PutUint32(payload[3:7], messageID)
	copy(payload[7:], data)
	return ssu2noise.NewSSU2Block(ssu2noise.BlockTypeFollowOnFragment, payload)
}
