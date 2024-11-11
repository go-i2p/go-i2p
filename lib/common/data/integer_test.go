package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntegerBigEndian(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	integer := Integer(bytes)

	assert.Equal(integer.Int(), 1, "Integer() did not parse bytes big endian")
}

func TestWorksWithOneByte(t *testing.T) {
	assert := assert.New(t)

	integer := Integer([]byte{0x01})

	assert.Equal(integer.Int(), 1, "Integer() did not correctly parse single byte slice")
}

func TestIsZeroWithNoData(t *testing.T) {
	assert := assert.New(t)

	integer := Integer([]byte{})

	assert.Equal(integer.Int(), 0, "Integer() did not correctly parse zero length byte slice")
}

func TestIntegerEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		size    int
		wantErr bool
		wantInt int
	}{
		{"empty input", []byte{}, 1, true, 0},
		{"zero size", []byte{1}, 0, true, 0},
		{"oversized", []byte{1}, 9, true, 0},
		{"valid small", []byte{42}, 1, false, 42},
		{"valid max", []byte{1, 2, 3, 4, 5, 6, 7, 8}, 8, false, 72623859790382856},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i, _, err := NewInteger(tt.input, tt.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewInteger() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && i.Int() != tt.wantInt {
				t.Errorf("Integer.Int() = %v, want %v", i.Int(), tt.wantInt)
			}
		})
	}
}
