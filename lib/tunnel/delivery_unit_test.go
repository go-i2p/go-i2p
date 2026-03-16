package tunnel

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

// buildTunnelDeliveryData builds a delivery instruction byte slice with
// flg as the flag byte, a fixed tunnel ID [0,0,0,1], and hash appended.
func buildTunnelDeliveryData(flg byte, hash []byte) []byte {
	data := []byte{flg}
	data = append(data, 0x00, 0x00, 0x00, 0x01) // tunnel ID
	data = append(data, hash...)
	return data
}

type DeliveryInstructionsFlags struct {
	FirstFragment bool
	Type          byte
	Delay         bool
}

func (dif DeliveryInstructionsFlags) FlagByte() byte {
	flag := byte(0x00)
	if !dif.FirstFragment {
		flag |= 0x01
	}
	flag |= dif.Type
	if dif.Delay {
		flag |= 0x10
	}
	return byte(flag)
}

func validFirstFragmentDeliveryInstructions(mapping common.Mapping) []byte {
	data := []byte{}

	flag := DeliveryInstructionsFlags{
		FirstFragment: true,
		Type:          0x02,
		Delay:         false,
	}
	data = append(data, flag.FlagByte())

	tunnel_id := []byte{0x00, 0x00, 0x00, 0x01}
	data = append(data, tunnel_id...)

	hash := make([]byte, HashSize)
	data = append(data, hash...)

	if flag.Delay {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}

	message_id := []byte{0x00, 0x00, 0x00, 0x02}
	data = append(data, message_id...)

	data = append(data, mapping.Data()...)

	return data
}

func TestReadDeliveryInstructions(t *testing.T) {
	assert := assert.New(t)

	mapping, _ := common.GoMapToMapping(map[string]string{})
	_, _, err := readDeliveryInstructions(
		validFirstFragmentDeliveryInstructions(
			*mapping,
		),
	)
	assert.Nil(err)
}

// TestDeliveryInstructionsHashTunnel tests Hash() method for DTTunnel delivery type
// This test verifies the variable shadowing bug fix where hash_start and hash_end
// must be reassigned (not redeclared) to adjust offsets correctly.
func TestDeliveryInstructionsHashTunnel(t *testing.T) {
	assertDeliveryInstructionHash(t,
		0x20,                           // DTTunnel flag
		[]byte{0x00, 0x00, 0x30, 0x39}, // tunnelID = 12345
		func(i int) byte { return byte(i) },
	)
}

// TestDeliveryInstructionsHashRouter tests Hash() method for DTRouter delivery type
func TestDeliveryInstructionsHashRouter(t *testing.T) {
	assertDeliveryInstructionHash(t,
		0x40, // DTRouter flag
		nil,  // no tunnelID
		func(i int) byte { return byte(255 - i) },
	)
}

// TestDeliveryInstructionsHashLocal tests Hash() method for DTLocal delivery type (error case)
func TestDeliveryInstructionsHashLocal(t *testing.T) {
	assert := assert.New(t)

	// Create a delivery instruction with DTLocal type
	// Format: flag(1) + ...
	data := []byte{}

	// Flag byte: bit 7=0 (first fragment), bits 5-4=00 (DTLocal), others=0
	flag := byte(0x00) // 0b00000000 = DTLocal
	data = append(data, flag)

	// Fragment size (2 bytes) - required for FirstFragment
	data = append(data, 0x00, 0x10)

	di, err := NewDeliveryInstructions(data)
	assert.Nil(err)

	// Call Hash() method - should return error
	_, err = di.Hash()

	// Verify error is returned
	assert.NotNil(err, "Hash() should return an error for DTLocal type")
	assert.Contains(err.Error(), "not of type DTTunnel or DTRouter", "Error message should mention valid delivery types")
}

// TestDeliveryInstructionsHashEmptyHash tests Hash() with all-zero hash value
func TestDeliveryInstructionsHashEmptyHash(t *testing.T) {
	assert := assert.New(t)

	// Create delivery instruction with DTTunnel and all-zero hash
	emptyHash := make([]byte, HashSize)
	data := buildTunnelDeliveryData(0x30, emptyHash) // DTTunnel + hasDelay

	// Delay byte (since flag 0x10 has both DTTunnel and hasDelay bits set)
	data = append(data, 0x00)

	// Fragment size (2 bytes)
	data = append(data, 0x00, 0x10)

	di, err := NewDeliveryInstructions(data)
	assert.Nil(err)

	resultHash, err := di.Hash()

	assert.Nil(err, "Hash() should not return error for valid delivery type")
	assert.Equal(HashSize, len(resultHash), "Hash should have correct length")
	assert.Equal(emptyHash, resultHash[:], "Empty hash should be returned as-is")
}

// TestDeliveryInstructionsHashInsufficientDataTunnel tests error handling for truncated TUNNEL data
func TestDeliveryInstructionsHashInsufficientDataTunnel(t *testing.T) {
	assert := assert.New(t)

	// Create delivery instruction with DTTunnel but insufficient data
	partialHash := make([]byte, 10)
	data := buildTunnelDeliveryData(0x20, partialHash) // DTTunnel without hasDelay

	_, err := NewDeliveryInstructions(data)

	assert.NotNil(err, "NewDeliveryInstructions should return error for insufficient data")
	assert.Contains(err.Error(), "insufficient data for hash", "Error should mention insufficient data")
}

// TestDeliveryInstructionsHashInsufficientDataRouter tests error handling for truncated ROUTER data
func TestDeliveryInstructionsHashInsufficientDataRouter(t *testing.T) {
	assert := assert.New(t)

	// Create delivery instruction with DTRouter but insufficient data
	data := []byte{}

	flag := byte(0x20) // DTRouter (2 << 4)
	data = append(data, flag)

	// Only partial hash (10 bytes instead of 32)
	partialHash := make([]byte, 10)
	data = append(data, partialHash...)

	_, err := NewDeliveryInstructions(data)

	assert.NotNil(err, "NewDeliveryInstructions should return error for insufficient data")
	assert.Contains(err.Error(), "insufficient data for hash", "Error should mention insufficient data")
}
