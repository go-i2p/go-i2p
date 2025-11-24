package netdb

import (
	"bytes"
	"testing"

	common "github.com/go-i2p/common/data"
)

// TestSelectFloodfillRouters_NoFloodfills tests selection when no floodfill routers exist
func TestSelectFloodfillRouters_NoFloodfills(t *testing.T) {
	db := NewStdNetDB("")

	targetHash := common.Hash{1, 2, 3, 4, 5}

	// Select from empty database - should return error
	result, err := db.SelectFloodfillRouters(targetHash, 3)

	if err == nil {
		t.Fatal("Expected error for empty NetDB, got nil")
	}

	if len(result) != 0 {
		t.Errorf("Expected 0 floodfills, got %d", len(result))
	}
}

// TestCalculateXORDistance tests XOR distance calculation
func TestCalculateXORDistance(t *testing.T) {
	db := NewStdNetDB("")

	tests := []struct {
		name string
		h1   common.Hash
		h2   common.Hash
		want []byte
	}{
		{
			name: "identical hashes",
			h1:   common.Hash{1, 2, 3},
			h2:   common.Hash{1, 2, 3},
			want: []byte{0, 0, 0},
		},
		{
			name: "different first byte",
			h1:   common.Hash{0xFF, 0, 0},
			h2:   common.Hash{0x00, 0, 0},
			want: []byte{0xFF, 0, 0},
		},
		{
			name: "XOR across multiple bytes",
			h1:   common.Hash{0xAA, 0xBB, 0xCC},
			h2:   common.Hash{0x55, 0x44, 0x33},
			want: []byte{0xFF, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := db.calculateXORDistance(tt.h1, tt.h2)
			if !bytes.Equal(got[:3], tt.want) {
				t.Errorf("calculateXORDistance() = %x, want %x", got[:3], tt.want)
			}
		})
	}
}

// TestCompareXORDistances tests distance comparison
func TestCompareXORDistances(t *testing.T) {
	db := NewStdNetDB("")

	tests := []struct {
		name string
		d1   []byte
		d2   []byte
		want bool // true if d1 < d2
	}{
		{
			name: "equal distances",
			d1:   []byte{1, 2, 3},
			d2:   []byte{1, 2, 3},
			want: false,
		},
		{
			name: "d1 less than d2",
			d1:   []byte{0, 0, 1},
			d2:   []byte{0, 0, 2},
			want: true,
		},
		{
			name: "d1 greater than d2",
			d1:   []byte{1, 0, 0},
			d2:   []byte{0, 255, 255},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := db.compareXORDistances(tt.d1, tt.d2)
			if got != tt.want {
				t.Errorf("compareXORDistances() = %v, want %v", got, tt.want)
			}
		})
	}
}
