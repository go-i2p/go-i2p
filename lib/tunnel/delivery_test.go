package tunnel

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

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

	hash := make([]byte, HASH_SIZE)
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

// TestDeliveryInstructionsHashTunnel tests Hash() method for DT_TUNNEL delivery type
// This test verifies the variable shadowing bug fix where hash_start and hash_end
// must be reassigned (not redeclared) to adjust offsets correctly.
func TestDeliveryInstructionsHashTunnel(t *testing.T) {
	assert := assert.New(t)

	// Create a delivery instruction with DT_TUNNEL type
	// Format: flag(1) + tunnel_id(4) + hash(32) + ...
	expectedHash := make([]byte, HASH_SIZE)
	for i := 0; i < HASH_SIZE; i++ {
		expectedHash[i] = byte(i)
	}

	data := []byte{}

	// Flag byte: bit 7=0 (first fragment), bits 6-5=01 (DT_TUNNEL), others=0
	flag := byte(0x20) // 0b00100000 = DT_TUNNEL (0x01 << 5)
	data = append(data, flag)

	// Tunnel ID (4 bytes)
	tunnelID := []byte{0x00, 0x00, 0x30, 0x39} // 12345 in big-endian
	data = append(data, tunnelID...)

	// Hash (32 bytes)
	data = append(data, expectedHash...)

	di := DeliveryInstructions(data)

	// Call Hash() method
	resultHash, err := di.Hash()

	// Verify no error and hash matches
	assert.Nil(err, "Hash() should not return an error for DT_TUNNEL type")
	assert.Equal(expectedHash, resultHash[:], "Hash should match the stored hash value")
}

// TestDeliveryInstructionsHashRouter tests Hash() method for DT_ROUTER delivery type
func TestDeliveryInstructionsHashRouter(t *testing.T) {
	assert := assert.New(t)

	// Create a delivery instruction with DT_ROUTER type
	// Format: flag(1) + hash(32) + ...
	expectedHash := make([]byte, HASH_SIZE)
	for i := 0; i < HASH_SIZE; i++ {
		expectedHash[i] = byte(255 - i)
	}

	data := []byte{}

	// Flag byte: bit 7=0 (first fragment), bits 6-5=10 (DT_ROUTER), others=0
	flag := byte(0x40) // 0b01000000 = DT_ROUTER (0x02 << 5)
	data = append(data, flag)

	// Hash (32 bytes) - immediately after flag for DT_ROUTER
	data = append(data, expectedHash...)

	di := DeliveryInstructions(data)

	// Call Hash() method
	resultHash, err := di.Hash()

	// Verify no error and hash matches
	assert.Nil(err, "Hash() should not return an error for DT_ROUTER type")
	assert.Equal(expectedHash, resultHash[:], "Hash should match the stored hash value")
}

// TestDeliveryInstructionsHashLocal tests Hash() method for DT_LOCAL delivery type (error case)
func TestDeliveryInstructionsHashLocal(t *testing.T) {
	assert := assert.New(t)

	// Create a delivery instruction with DT_LOCAL type
	// Format: flag(1) + ...
	data := []byte{}

	// Flag byte: bit 7=0 (first fragment), bits 6-5=00 (DT_LOCAL), others=0
	flag := byte(0x00) // 0b00000000 = DT_LOCAL
	data = append(data, flag)

	di := DeliveryInstructions(data)

	// Call Hash() method - should return error
	_, err := di.Hash()

	// Verify error is returned
	assert.NotNil(err, "Hash() should return an error for DT_LOCAL type")
	assert.Contains(err.Error(), "not of type DT_TUNNEL or DT_ROUTER", "Error message should mention valid delivery types")
}

// TestDeliveryInstructionsHashEmptyHash tests Hash() with all-zero hash value
func TestDeliveryInstructionsHashEmptyHash(t *testing.T) {
	assert := assert.New(t)

	// Create delivery instruction with DT_TUNNEL and all-zero hash
	data := []byte{}

	flag := byte(0x20) // DT_TUNNEL
	data = append(data, flag)

	tunnelID := []byte{0x00, 0x00, 0x00, 0x01}
	data = append(data, tunnelID...)

	// All-zero hash
	emptyHash := make([]byte, HASH_SIZE)
	data = append(data, emptyHash...)

	di := DeliveryInstructions(data)

	resultHash, err := di.Hash()

	assert.Nil(err, "Hash() should not return error for valid delivery type")
	assert.Equal(HASH_SIZE, len(resultHash), "Hash should have correct length")
	assert.Equal(emptyHash, resultHash[:], "Empty hash should be returned as-is")
}

// TestDeliveryInstructionsHashInsufficientDataTunnel tests error handling for truncated TUNNEL data
func TestDeliveryInstructionsHashInsufficientDataTunnel(t *testing.T) {
	assert := assert.New(t)

	// Create delivery instruction with DT_TUNNEL but insufficient data
	data := []byte{}

	flag := byte(0x20) // DT_TUNNEL
	data = append(data, flag)

	tunnelID := []byte{0x00, 0x00, 0x00, 0x01}
	data = append(data, tunnelID...)

	// Only partial hash (10 bytes instead of 32)
	partialHash := make([]byte, 10)
	data = append(data, partialHash...)

	di := DeliveryInstructions(data)

	_, err := di.Hash()

	assert.NotNil(err, "Hash() should return error for insufficient data")
	assert.Contains(err.Error(), "not contain enough data", "Error should mention insufficient data")
}

// TestDeliveryInstructionsHashInsufficientDataRouter tests error handling for truncated ROUTER data
func TestDeliveryInstructionsHashInsufficientDataRouter(t *testing.T) {
	assert := assert.New(t)

	// Create delivery instruction with DT_ROUTER but insufficient data
	data := []byte{}

	flag := byte(0x40) // DT_ROUTER
	data = append(data, flag)

	// Only partial hash (10 bytes instead of 32)
	partialHash := make([]byte, 10)
	data = append(data, partialHash...)

	di := DeliveryInstructions(data)

	_, err := di.Hash()

	assert.NotNil(err, "Hash() should return error for insufficient data")
	assert.Contains(err.Error(), "not contain enough data", "Error should mention insufficient data")
}
