package i2np

import (
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestByteReader_ReadByte(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    byte
		wantErr bool
	}{
		{
			name: "read single byte",
			data: []byte{0x42},
			want: 0x42,
		},
		{
			name:    "empty buffer",
			data:    []byte{},
			wantErr: true,
		},
		{
			name: "read multiple bytes sequentially",
			data: []byte{0x01, 0x02, 0x03},
			want: 0x01,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := NewByteReader(tt.data)
			got, err := br.ReadByte()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestByteReader_ReadInt(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    int
		wantErr bool
	}{
		{
			name: "read 4-byte big-endian int",
			data: []byte{0x00, 0x00, 0x00, 0x42},
			want: 0x42,
		},
		{
			name: "read large int",
			data: []byte{0x12, 0x34, 0x56, 0x78},
			want: 0x12345678,
		},
		{
			name:    "not enough data",
			data:    []byte{0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "empty buffer",
			data:    []byte{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := NewByteReader(tt.data)
			got, err := br.ReadInt()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestByteReader_ReadInt64(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    int64
		wantErr bool
	}{
		{
			name: "read 8-byte big-endian int64",
			data: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42},
			want: 0x42,
		},
		{
			name: "read large int64",
			data: []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
			want: 0x123456789abcdef0,
		},
		{
			name:    "not enough data",
			data:    []byte{0x00, 0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "empty buffer",
			data:    []byte{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := NewByteReader(tt.data)
			got, err := br.ReadInt64()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestByteReader_ReadDate(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name: "read valid date",
			data: []byte{0x00, 0x00, 0x01, 0x7f, 0xff, 0xff, 0xff, 0xff},
		},
		{
			name:    "not enough data",
			data:    []byte{0x00, 0x00, 0x00, 0x00},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := NewByteReader(tt.data)
			got, err := br.ReadDate()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotZero(t, got)
		})
	}
}

func TestByteReader_ReadBytes(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		n       int
		want    []byte
		wantErr bool
	}{
		{
			name: "read exact amount",
			data: []byte{0x01, 0x02, 0x03, 0x04},
			n:    2,
			want: []byte{0x01, 0x02},
		},
		{
			name:    "read more than available",
			data:    []byte{0x01, 0x02},
			n:       5,
			wantErr: true,
		},
		{
			name:    "read negative length",
			data:    []byte{0x01, 0x02},
			n:       -1,
			wantErr: true,
		},
		{
			name: "read zero bytes",
			data: []byte{0x01, 0x02},
			n:    0,
			want: []byte{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := NewByteReader(tt.data)
			got, err := br.ReadBytes(tt.n)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestByteReader_ReadHash(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name: "read valid 32-byte hash",
			data: make([]byte, 32),
		},
		{
			name:    "not enough data for hash",
			data:    make([]byte, 20),
			wantErr: true,
		},
		{
			name:    "empty buffer",
			data:    []byte{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := NewByteReader(tt.data)
			got, err := br.ReadHash()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, data.Hash{}, got)
		})
	}
}

func TestByteReader_OffsetAndRemaining(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	br := NewByteReader(data)

	assert.Equal(t, 0, br.Offset())
	assert.Equal(t, 8, br.Remaining())

	br.ReadByte()
	assert.Equal(t, 1, br.Offset())
	assert.Equal(t, 7, br.Remaining())

	br.ReadInt()
	assert.Equal(t, 5, br.Offset())
	assert.Equal(t, 3, br.Remaining())
}

func TestByteReader_Peek(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	br := NewByteReader(data)

	// Peek without advancing
	peeked, err := br.Peek(2)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x02}, peeked)
	assert.Equal(t, 0, br.Offset())

	// Read after peek
	read, err := br.ReadBytes(2)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x02}, read)
	assert.Equal(t, 2, br.Offset())

	// Peek beyond available
	_, err = br.Peek(10)
	assert.Error(t, err)
}

func TestByteReader_Reset(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	br := NewByteReader(data)

	br.ReadInt()
	assert.Equal(t, 4, br.Offset())

	br.Reset()
	assert.Equal(t, 0, br.Offset())

	read, err := br.ReadByte()
	require.NoError(t, err)
	assert.Equal(t, byte(0x01), read)
}

func TestByteReader_SequentialReads(t *testing.T) {
	// Create a buffer with known structure: 1 byte + 4-byte int + 8-byte int64
	data := make([]byte, 13)
	data[0] = 0x42
	data[1] = 0x00
	data[2] = 0x00
	data[3] = 0x00
	data[4] = 0x10
	copy(data[5:], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20})

	br := NewByteReader(data)

	// Read in sequence
	b, err := br.ReadByte()
	require.NoError(t, err)
	assert.Equal(t, byte(0x42), b)
	assert.Equal(t, 1, br.Offset())

	i, err := br.ReadInt()
	require.NoError(t, err)
	assert.Equal(t, 0x10, i)
	assert.Equal(t, 5, br.Offset())

	i64, err := br.ReadInt64()
	require.NoError(t, err)
	assert.Equal(t, int64(0x20), i64)
	assert.Equal(t, 13, br.Offset())

	// Try to read beyond
	_, err = br.ReadByte()
	assert.Error(t, err)
}

func TestByteReader_NotAdvancedOnError(t *testing.T) {
	data := []byte{0x01}
	br := NewByteReader(data)

	// Try to read 4 bytes (should fail)
	_, err := br.ReadInt()
	assert.Error(t, err)
	assert.Equal(t, 0, br.Offset()) // Offset should not advance

	// Now read the available byte
	b, err := br.ReadByte()
	require.NoError(t, err)
	assert.Equal(t, byte(0x01), b)
	assert.Equal(t, 1, br.Offset())
}

// Benchmark for performance comparison with manual offset tracking
func BenchmarkByteReader_ReadInt(b *testing.B) {
	data := make([]byte, 1024*100) // 100KB
	for i := 0; i < len(data)-3; i += 4 {
		data[i] = 0x12
		data[i+1] = 0x34
		data[i+2] = 0x56
		data[i+3] = 0x78
	}

	b.ResetTimer()
	br := NewByteReader(data)
	for i := 0; i < b.N; i++ {
		br.Reset()
		for br.Remaining() >= 4 {
			_, _ = br.ReadInt()
		}
	}
}
