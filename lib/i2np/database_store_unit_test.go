package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
)

// TestDatabaseStore_GetLeaseSetType verifies that the type field is correctly parsed
// according to the I2P specification (bits 3-0 indicate LeaseSet variant)
func TestDatabaseStore_GetLeaseSetType(t *testing.T) {
	tests := []struct {
		name         string
		typeField    byte
		expectedType int
		description  string
	}{
		{
			name:         "RouterInfo",
			typeField:    0x00,
			expectedType: DATABASE_STORE_TYPE_ROUTER_INFO,
			description:  "Type 0 should be RouterInfo",
		},
		{
			name:         "Original LeaseSet",
			typeField:    0x01,
			expectedType: DATABASE_STORE_TYPE_LEASESET,
			description:  "Type 1 should be original LeaseSet (deprecated)",
		},
		{
			name:         "LeaseSet2",
			typeField:    0x03,
			expectedType: DATABASE_STORE_TYPE_LEASESET2,
			description:  "Type 3 should be LeaseSet2 (standard)",
		},
		{
			name:         "EncryptedLeaseSet",
			typeField:    0x05,
			expectedType: DATABASE_STORE_TYPE_ENCRYPTED_LEASESET,
			description:  "Type 5 should be EncryptedLeaseSet",
		},
		{
			name:         "MetaLeaseSet",
			typeField:    0x07,
			expectedType: DATABASE_STORE_TYPE_META_LEASESET,
			description:  "Type 7 should be MetaLeaseSet",
		},
		{
			name:         "Type with high bits set (should be masked)",
			typeField:    0xF3, // bits 7-4 set, bits 3-0 = 0x3
			expectedType: DATABASE_STORE_TYPE_LEASESET2,
			description:  "High bits should be ignored, only bits 3-0 matter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := &DatabaseStore{
				StoreType: tt.typeField,
			}

			result := ds.GetLeaseSetType()
			if result != tt.expectedType {
				t.Errorf("%s: got type %d, want %d", tt.description, result, tt.expectedType)
			}
		})
	}
}

// TestDatabaseStore_IsRouterInfo verifies RouterInfo type detection
func TestDatabaseStore_IsRouterInfo(t *testing.T) {
	tests := []struct {
		name      string
		typeField byte
		expected  bool
	}{
		{"RouterInfo type 0", 0x00, true},
		{"LeaseSet type 1", 0x01, false},
		{"LeaseSet2 type 3", 0x03, false},
		{"EncryptedLeaseSet type 5", 0x05, false},
		{"MetaLeaseSet type 7", 0x07, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := &DatabaseStore{StoreType: tt.typeField}
			if got := ds.IsRouterInfo(); got != tt.expected {
				t.Errorf("IsRouterInfo() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestDatabaseStore_IsLeaseSet verifies LeaseSet type detection (any variant)
func TestDatabaseStore_IsLeaseSet(t *testing.T) {
	tests := []struct {
		name      string
		typeField byte
		expected  bool
	}{
		{"RouterInfo should not be LeaseSet", 0x00, false},
		{"Original LeaseSet", 0x01, true},
		{"LeaseSet2", 0x03, true},
		{"EncryptedLeaseSet", 0x05, true},
		{"MetaLeaseSet", 0x07, true},
		{"Unknown type 2", 0x02, false},
		{"Unknown type 4", 0x04, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := &DatabaseStore{StoreType: tt.typeField}
			if got := ds.IsLeaseSet(); got != tt.expected {
				t.Errorf("IsLeaseSet() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestDatabaseStore_IsLeaseSet2 verifies LeaseSet2 specific detection
func TestDatabaseStore_IsLeaseSet2(t *testing.T) {
	tests := []struct {
		name      string
		typeField byte
		expected  bool
	}{
		{"RouterInfo", 0x00, false},
		{"Original LeaseSet", 0x01, false},
		{"LeaseSet2", 0x03, true},
		{"LeaseSet2 with high bits", 0xF3, true}, // Should mask high bits
		{"EncryptedLeaseSet", 0x05, false},
		{"MetaLeaseSet", 0x07, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := &DatabaseStore{StoreType: tt.typeField}
			if got := ds.IsLeaseSet2(); got != tt.expected {
				t.Errorf("IsLeaseSet2() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestDatabaseStore_NewDatabaseStore verifies constructor creates valid DatabaseStore
func TestDatabaseStore_NewDatabaseStore(t *testing.T) {
	key := common.Hash{1, 2, 3, 4, 5, 6, 7, 8}
	data := []byte{10, 20, 30, 40}
	dataType := byte(DATABASE_STORE_TYPE_LEASESET2)

	ds := NewDatabaseStore(key, data, dataType)

	if ds.Key != key {
		t.Errorf("Key not set correctly")
	}
	if ds.StoreType != dataType {
		t.Errorf("Type = %d, want %d", ds.StoreType, dataType)
	}
	if len(ds.Data) != len(data) {
		t.Errorf("Data length = %d, want %d", len(ds.Data), len(data))
	}
	// Verify no reply token set
	zeroToken := [4]byte{0, 0, 0, 0}
	if ds.ReplyToken != zeroToken {
		t.Errorf("ReplyToken should be zero")
	}
}

// TestDatabaseStore_MarshalBinary verifies serialization for different types
func TestDatabaseStore_MarshalBinary(t *testing.T) {
	tests := []struct {
		name           string
		store          *DatabaseStore
		expectedMinLen int
		description    string
	}{
		{
			name: "RouterInfo without reply",
			store: &DatabaseStore{
				Key:           common.Hash{1, 2, 3},
				StoreType:     DATABASE_STORE_TYPE_ROUTER_INFO,
				ReplyToken:    [4]byte{0, 0, 0, 0},
				ReplyTunnelID: [4]byte{0, 0, 0, 0},
				Data:          []byte{10, 20, 30},
			},
			expectedMinLen: 32 + 1 + 4 + 3, // key + type + replyToken + data
			description:    "RouterInfo should serialize without reply fields",
		},
		{
			name: "LeaseSet2 without reply",
			store: &DatabaseStore{
				Key:           common.Hash{5, 6, 7},
				StoreType:     DATABASE_STORE_TYPE_LEASESET2,
				ReplyToken:    [4]byte{0, 0, 0, 0},
				ReplyTunnelID: [4]byte{0, 0, 0, 0},
				Data:          []byte{40, 50},
			},
			expectedMinLen: 32 + 1 + 4 + 2, // key + type + replyToken + data
			description:    "LeaseSet2 should serialize correctly",
		},
		{
			name: "LeaseSet with reply token",
			store: &DatabaseStore{
				Key:           common.Hash{8, 9, 10},
				StoreType:     DATABASE_STORE_TYPE_LEASESET,
				ReplyToken:    [4]byte{0, 0, 0, 1},
				ReplyTunnelID: [4]byte{0, 0, 0, 100},
				ReplyGateway:  common.Hash{11, 12, 13},
				Data:          []byte{60, 70, 80, 90},
			},
			expectedMinLen: 32 + 1 + 4 + 4 + 32 + 4, // key + type + replyToken + tunnelID + gateway + data
			description:    "Should include reply fields when token is set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use MarshalPayload to get just the type-specific payload
			// (MarshalBinary now includes the I2NP header)
			data, err := tt.store.MarshalPayload()
			if err != nil {
				t.Fatalf("%s: MarshalPayload() error = %v", tt.description, err)
			}
			if len(data) < tt.expectedMinLen {
				t.Errorf("%s: serialized length = %d, want >= %d",
					tt.description, len(data), tt.expectedMinLen)
			}

			// Verify key is at start
			if data[0] != tt.store.Key[0] {
				t.Errorf("Key not serialized correctly at start of data")
			}

			// Verify type field at offset 32
			if data[32] != tt.store.StoreType {
				t.Errorf("Type field = %d, want %d", data[32], tt.store.StoreType)
			}
		})
	}
}

// TestDatabaseStore_Getters verifies all getter methods
func TestDatabaseStore_Getters(t *testing.T) {
	key := common.Hash{100, 101, 102}
	data := []byte{200, 201, 202}
	storeType := byte(DATABASE_STORE_TYPE_LEASESET2)

	ds := &DatabaseStore{
		Key:       key,
		StoreType: storeType,
		Data:      data,
	}

	if got := ds.GetStoreKey(); got != key {
		t.Errorf("GetStoreKey() != key")
	}

	if got := ds.GetStoreType(); got != storeType {
		t.Errorf("GetStoreType() = %d, want %d", got, storeType)
	}

	if got := ds.GetStoreData(); len(got) != len(data) {
		t.Errorf("GetStoreData() length = %d, want %d", len(got), len(data))
	}
}

// TestDatabaseStore_TypeConstants verifies type constants have correct values per spec
func TestDatabaseStore_TypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant int
		expected int
	}{
		{"RouterInfo", DATABASE_STORE_TYPE_ROUTER_INFO, 0},
		{"LeaseSet", DATABASE_STORE_TYPE_LEASESET, 1},
		{"LeaseSet2", DATABASE_STORE_TYPE_LEASESET2, 3},
		{"EncryptedLeaseSet", DATABASE_STORE_TYPE_ENCRYPTED_LEASESET, 5},
		{"MetaLeaseSet", DATABASE_STORE_TYPE_META_LEASESET, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s constant = %d, want %d (per I2P spec)",
					tt.name, tt.constant, tt.expected)
			}
		})
	}
}
