package ntcp2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	assert.Equal(t, uint8(0), opts.Version)
	assert.Equal(t, float64(0), opts.PaddingMin)
	assert.Equal(t, float64(0), opts.PaddingMax)
	assert.Equal(t, uint16(0), opts.DummyMin)
	assert.Equal(t, uint16(0), opts.DummyMax)
	assert.Equal(t, uint16(0), opts.DelayMin)
	assert.Equal(t, uint16(0), opts.DelayMax)
}

func TestOptions_SerializeAndParse(t *testing.T) {
	opts := &Options{
		Version:    0,
		PaddingMin: 1.5,
		PaddingMax: 3.0,
		DummyMin:   10,
		DummyMax:   60,
		DelayMin:   100,
		DelayMax:   500,
	}

	data := opts.Serialize()
	assert.Len(t, data, optionsBlockMinSize)

	parsed, err := ParseOptions(data)
	require.NoError(t, err)

	assert.Equal(t, opts.Version, parsed.Version)
	// 4.4 fixed-point has limited precision — check within tolerance
	assert.InDelta(t, opts.PaddingMin, parsed.PaddingMin, 0.1)
	assert.InDelta(t, opts.PaddingMax, parsed.PaddingMax, 0.1)
	assert.Equal(t, opts.DummyMin, parsed.DummyMin)
	assert.Equal(t, opts.DummyMax, parsed.DummyMax)
	assert.Equal(t, opts.DelayMin, parsed.DelayMin)
	assert.Equal(t, opts.DelayMax, parsed.DelayMax)
}

func TestParseOptions_TooShort(t *testing.T) {
	_, err := ParseOptions([]byte{0x00, 0x01})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestFixed44_Encoding(t *testing.T) {
	tests := []struct {
		input    float64
		expected float64
	}{
		{0.0, 0.0},
		{1.0, 1.0},
		{0.5, 0.5},
		{15.9375, 15.9375},
		{7.25, 7.25},
	}

	for _, tt := range tests {
		encoded := encodeFixed44(tt.input)
		decoded := decodeFixed44(encoded)
		assert.InDelta(t, tt.expected, decoded, 0.0625,
			"round-trip for %f: encoded=%02x decoded=%f", tt.input, encoded, decoded)
	}
}

func TestFixed44_Clamping(t *testing.T) {
	// Values outside [0, 15.9375] should be clamped
	assert.Equal(t, byte(0x00), encodeFixed44(-1.0))
	assert.Equal(t, byte(0xFF), encodeFixed44(100.0))
}

func TestNewOptionsBlock(t *testing.T) {
	opts := DefaultOptions()
	block := NewOptionsBlock(opts)
	assert.Equal(t, BlockTypeOptions, block.Type)
	assert.Len(t, block.Data, optionsBlockMinSize)

	// Should round-trip through block serialization
	payload := SerializeBlocks(block)
	blocks, err := ParseBlocks(payload)
	require.NoError(t, err)
	require.Len(t, blocks, 1)

	parsed, err := ParseOptions(blocks[0].Data)
	require.NoError(t, err)
	assert.Equal(t, opts.Version, parsed.Version)
}
