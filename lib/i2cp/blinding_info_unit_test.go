package i2cp

import (
	"bytes"
	"testing"
)

func TestBlindingInfoPayloadParse(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantEnabled bool
		wantSecret  []byte
		shouldError bool
	}{
		{
			name:        "disabled",
			data:        []byte{0x00},
			wantEnabled: false,
			wantSecret:  nil,
			shouldError: false,
		},
		{
			name:        "enabled_no_secret",
			data:        []byte{0x01},
			wantEnabled: true,
			wantSecret:  nil,
			shouldError: false,
		},
		{
			name: "enabled_with_secret",
			data: func() []byte {
				result := []byte{0x01}
				secret := make([]byte, 32)
				for i := range secret {
					secret[i] = byte(i)
				}
				result = append(result, secret...)
				return result
			}(),
			wantEnabled: true,
			wantSecret: func() []byte {
				secret := make([]byte, 32)
				for i := range secret {
					secret[i] = byte(i)
				}
				return secret
			}(),
			shouldError: false,
		},
		{
			name:        "empty",
			data:        []byte{},
			shouldError: true,
		},
		{
			name:        "invalid_secret_length_short",
			data:        []byte{0x01, 0x11, 0x22, 0x33}, // Only 3 bytes of secret
			shouldError: true,
		},
		{
			name: "invalid_secret_length_long",
			data: func() []byte {
				result := []byte{0x01}
				result = append(result, make([]byte, 33)...) // 33 bytes of secret
				return result
			}(),
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := ParseBlindingInfoPayload(tt.data)

			if tt.shouldError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if payload.Enabled != tt.wantEnabled {
				t.Errorf("Enabled = %v, want %v", payload.Enabled, tt.wantEnabled)
			}

			if !bytes.Equal(payload.Secret, tt.wantSecret) {
				t.Errorf("Secret = %v, want %v", payload.Secret, tt.wantSecret)
			}
		})
	}
}

func TestBlindingInfoPayloadMarshal(t *testing.T) {
	tests := []struct {
		name        string
		payload     *BlindingInfoPayload
		wantSize    int
		shouldError bool
	}{
		{
			name: "disabled",
			payload: &BlindingInfoPayload{
				Enabled: false,
				Secret:  nil,
			},
			wantSize:    1,
			shouldError: false,
		},
		{
			name: "enabled_no_secret",
			payload: &BlindingInfoPayload{
				Enabled: true,
				Secret:  nil,
			},
			wantSize:    1,
			shouldError: false,
		},
		{
			name: "enabled_with_secret",
			payload: &BlindingInfoPayload{
				Enabled: true,
				Secret:  make([]byte, 32),
			},
			wantSize:    33,
			shouldError: false,
		},
		{
			name: "invalid_secret_length",
			payload: &BlindingInfoPayload{
				Enabled: true,
				Secret:  make([]byte, 16), // Wrong length
			},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()

			if tt.shouldError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("MarshalBinary() error: %v", err)
			}

			if len(data) != tt.wantSize {
				t.Errorf("data length = %d, want %d", len(data), tt.wantSize)
			}

			// Verify enabled flag
			if tt.payload.Enabled && data[0] != 0x01 {
				t.Errorf("enabled flag = 0x%02x, want 0x01", data[0])
			} else if !tt.payload.Enabled && data[0] != 0x00 {
				t.Errorf("enabled flag = 0x%02x, want 0x00", data[0])
			}

			// Verify secret if present
			if tt.payload.Enabled && len(tt.payload.Secret) == 32 {
				if !bytes.Equal(data[1:33], tt.payload.Secret) {
					t.Error("marshaled secret does not match input")
				}
			}
		})
	}
}

func TestBlindingInfoRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload *BlindingInfoPayload
	}{
		{
			name: "disabled",
			payload: &BlindingInfoPayload{
				Enabled: false,
				Secret:  nil,
			},
		},
		{
			name: "enabled_no_secret",
			payload: &BlindingInfoPayload{
				Enabled: true,
				Secret:  nil,
			},
		},
		{
			name: "enabled_with_secret",
			payload: &BlindingInfoPayload{
				Enabled: true,
				Secret: func() []byte {
					secret := make([]byte, 32)
					for i := range secret {
						secret[i] = byte(i * 7 % 256)
					}
					return secret
				}(),
			},
		},
		{
			name: "enabled_with_zero_secret",
			payload: &BlindingInfoPayload{
				Enabled: true,
				Secret:  make([]byte, 32),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error: %v", err)
			}

			parsed, err := ParseBlindingInfoPayload(data)
			if err != nil {
				t.Fatalf("ParseBlindingInfoPayload() error: %v", err)
			}

			if parsed.Enabled != tt.payload.Enabled {
				t.Errorf("Enabled = %v, want %v", parsed.Enabled, tt.payload.Enabled)
			}

			if !bytes.Equal(parsed.Secret, tt.payload.Secret) {
				t.Errorf("Secret mismatch after round trip")
			}
		})
	}
}

func TestBlindingInfoConstants(t *testing.T) {
	if MessageTypeBlindingInfo != 42 {
		t.Errorf("MessageTypeBlindingInfo = %d, want 42", MessageTypeBlindingInfo)
	}

	if name := MessageTypeName(MessageTypeBlindingInfo); name != "BlindingInfo" {
		t.Errorf("MessageTypeName(BlindingInfo) = %q, want %q", name, "BlindingInfo")
	}
}

func TestBlindingInfoEnableDisable(t *testing.T) {
	// Test enabling blinding
	enablePayload := &BlindingInfoPayload{
		Enabled: true,
		Secret:  nil, // Random secret will be generated
	}
	enableData, err := enablePayload.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error: %v", err)
	}
	if len(enableData) != 1 {
		t.Errorf("enable payload length = %d, want 1", len(enableData))
	}
	if enableData[0] != 0x01 {
		t.Errorf("enable flag = 0x%02x, want 0x01", enableData[0])
	}

	// Test disabling blinding
	disablePayload := &BlindingInfoPayload{
		Enabled: false,
		Secret:  nil,
	}
	disableData, err := disablePayload.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error: %v", err)
	}
	if len(disableData) != 1 {
		t.Errorf("disable payload length = %d, want 1", len(disableData))
	}
	if disableData[0] != 0x00 {
		t.Errorf("disable flag = 0x%02x, want 0x00", disableData[0])
	}
}

func TestBlindingInfoSecretFormats(t *testing.T) {
	tests := []struct {
		name   string
		secret []byte
		valid  bool
	}{
		{
			name:   "nil_secret",
			secret: nil,
			valid:  true,
		},
		{
			name:   "valid_32_byte_secret",
			secret: make([]byte, 32),
			valid:  true,
		},
		{
			name:   "all_ones_secret",
			secret: bytes.Repeat([]byte{0xFF}, 32),
			valid:  true,
		},
		{
			name:   "all_zeros_secret",
			secret: bytes.Repeat([]byte{0x00}, 32),
			valid:  true,
		},
		{
			name:   "invalid_16_bytes",
			secret: make([]byte, 16),
			valid:  false,
		},
		{
			name:   "invalid_64_bytes",
			secret: make([]byte, 64),
			valid:  false,
		},
		{
			name:   "invalid_1_byte",
			secret: []byte{0x42},
			valid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := &BlindingInfoPayload{
				Enabled: true,
				Secret:  tt.secret,
			}

			data, err := payload.MarshalBinary()

			if tt.valid {
				if err != nil {
					t.Errorf("unexpected error for valid secret: %v", err)
				}
				if tt.secret != nil && len(data) != 33 {
					t.Errorf("data length = %d, want 33", len(data))
				}
				if tt.secret == nil && len(data) != 1 {
					t.Errorf("data length = %d, want 1", len(data))
				}
			} else {
				if err == nil {
					t.Error("expected error for invalid secret length but got none")
				}
			}
		})
	}
}
