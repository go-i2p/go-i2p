// Tests for SSU2 I2NP fragmentation. The live send path is
// sendWithCongestionControl -> marshalI2NPShort -> fragmentSSU2Short, which
// emits the spec's FirstFragment (type 4) / FollowOnFragment (type 5) wire
// formats. These tests lock that format down; the previous non-standard
// encoder (FragmentI2NPMessage / FrameI2NPToBlock) was dead code and was
// removed, so its tests are gone with it.

package ssu2

import (
	"encoding/binary"
	"testing"

	"github.com/go-i2p/go-i2p/lib/i2np"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reassembleSSU2Short reassembles a block list produced by fragmentSSU2Short
// back into the original short-header bytes, following the spec layout:
// FirstFragment: Type(1)+MessageID(4)+ShortExpiry(4)+BodyChunk
// FollowOnFragment: FragInfo(1)+MessageID(4)+BodyChunk
func reassembleSSU2Short(t *testing.T, blocks []*ssu2noise.SSU2Block) []byte {
	t.Helper()
	var out []byte
	var expectedID uint32
	for i, b := range blocks {
		switch b.Type {
		case ssu2noise.BlockTypeI2NPMessage:
			require.Equal(t, 0, i, "unfragmented I2NP block must be the only block")
			out = append(out, b.Data...)
		case ssu2noise.BlockTypeFirstFragment:
			require.GreaterOrEqual(t, len(b.Data), 9, "first fragment carries the 9-byte short header")
			expectedID = binary.BigEndian.Uint32(b.Data[1:5])
			out = append(out, b.Data...)
		case ssu2noise.BlockTypeFollowOnFragment:
			require.GreaterOrEqual(t, len(b.Data), 5)
			require.Equal(t, expectedID, binary.BigEndian.Uint32(b.Data[1:5]),
				"follow-on must echo the same message ID")
			out = append(out, b.Data[5:]...)
		default:
			t.Fatalf("unexpected block type %d", b.Type)
		}
	}
	return out
}

func TestFragmentSSU2Short_NoFragmentation(t *testing.T) {
	data := make([]byte, 500)
	copy(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}) // 9-byte short header prefix
	blocks, err := fragmentSSU2Short(data, maxSSU2PayloadIPv4)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, ssu2noise.BlockTypeI2NPMessage, blocks[0].Type)
	assert.Equal(t, data, blocks[0].Data)
}

func TestFragmentSSU2Short_RequiresFragmentation(t *testing.T) {
	const messageID = uint32(0x11223344)
	body := make([]byte, 3000)
	for i := range body {
		body[i] = byte(i)
	}
	data := make([]byte, 9+len(body))
	data[0] = byte(i2np.I2NPMessageTypeData)
	binary.BigEndian.PutUint32(data[1:5], messageID)
	binary.BigEndian.PutUint32(data[5:9], 0xdeadbeef)
	copy(data[9:], body)

	blocks, err := fragmentSSU2Short(data, 200)
	require.NoError(t, err)
	require.Greater(t, len(blocks), 1)

	assert.Equal(t, ssu2noise.BlockTypeFirstFragment, blocks[0].Type)
	require.GreaterOrEqual(t, len(blocks[0].Data), 9)
	assert.Equal(t, data[0], blocks[0].Data[0], "first fragment carries the I2NP type")
	assert.Equal(t, messageID, binary.BigEndian.Uint32(blocks[0].Data[1:5]))
	assert.Equal(t, uint32(0xdeadbeef), binary.BigEndian.Uint32(blocks[0].Data[5:9]))

	for _, b := range blocks[1:] {
		assert.Equal(t, ssu2noise.BlockTypeFollowOnFragment, b.Type)
	}
	// Last fragment must have its isLast bit set in FragInfo (bit 0).
	last := blocks[len(blocks)-1]
	assert.Equal(t, byte(1), last.Data[0]&0x01, "last follow-on sets isLast")
	// Intermediate follow-ons must not.
	if len(blocks) > 2 {
		assert.Equal(t, byte(0), blocks[1].Data[0]&0x01)
	}

	// Round-trip: reassembly must reproduce the original bytes exactly.
	got := reassembleSSU2Short(t, blocks)
	assert.Equal(t, data, got)
}

func TestFragmentSSU2Short_FragmentNumbersIncrement(t *testing.T) {
	data := make([]byte, 9+2000)
	data[0] = byte(i2np.I2NPMessageTypeData)
	binary.BigEndian.PutUint32(data[1:5], 42)
	blocks, err := fragmentSSU2Short(data, 300)
	require.NoError(t, err)
	for i, b := range blocks[1:] {
		fragNum := b.Data[0] >> 1
		assert.Equal(t, uint8(i+1), fragNum, "follow-on fragment numbers start at 1 and increment")
	}
}

func TestFragmentSSU2Short_TooSmallPayload(t *testing.T) {
	data := make([]byte, 9+100)
	_, err := fragmentSSU2Short(data, 8)
	assert.Error(t, err, "payload smaller than the fragment header must be rejected")
}

func TestFragmentSSU2Short_DataTooShort(t *testing.T) {
	// maxPayload below len(data)+TLV so the single-block shortcut is skipped
	// and the short-header guard is reached.
	_, err := fragmentSSU2Short([]byte{1, 2, 3}, 3)
	assert.Error(t, err, "data shorter than the 9-byte short header must be rejected")
}

// TestFragmentSSU2Short_ViaLiveSendPath proves the encoder is the one the live
// path uses end-to-end for a real typed message.
func TestFragmentSSU2Short_ViaLiveSendPath(t *testing.T) {
	msg := i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeData)
	msg.SetData(make([]byte, 4000))
	data, err := marshalI2NPShort(msg)
	require.NoError(t, err)
	blocks, err := fragmentSSU2Short(data, maxSSU2PayloadIPv6)
	require.NoError(t, err)
	require.Greater(t, len(blocks), 1)
	assert.Equal(t, data, reassembleSSU2Short(t, blocks))
}
