package i2cp

import (
	"testing"
	"time"

	"github.com/go-i2p/common/data"
)

// TestParseCreateSessionPayload_Empty tests parsing with empty/minimal payload
func TestParseCreateSessionPayload_Empty(t *testing.T) {
	// Empty payload
	_, _, err := ParseCreateSessionPayload([]byte{})
	if err == nil {
		t.Error("Expected error for empty payload, got nil")
	}

	// Too short payload
	_, _, err = ParseCreateSessionPayload([]byte{0x01})
	if err == nil {
		t.Error("Expected error for too short payload, got nil")
	}
}

// TestParseCreateSessionPayload_DefaultOptions tests parsing with default options (empty mapping)
func TestParseCreateSessionPayload_DefaultOptions(t *testing.T) {
	// Create a test destination
	dest, err := createTestDestination()
	if err != nil {
		t.Fatalf("Failed to create test destination: %v", err)
	}

	// Serialize destination
	destBytes, err := dest.Bytes()
	if err != nil {
		t.Fatalf("Failed to serialize destination: %v", err)
	}

	// Create empty options mapping - just 2 bytes for size=0
	// This is the minimal valid mapping format
	mappingBytes := []byte{0x00, 0x00} // Size = 0 (no options)

	// Combine destination + empty mapping
	payload := append(destBytes, mappingBytes...)

	// Parse
	parsedDest, config, err := ParseCreateSessionPayload(payload)
	if err != nil {
		t.Fatalf("Failed to parse create session payload: %v", err)
	}

	// Verify destination parsed correctly
	if parsedDest == nil {
		t.Fatal("Parsed destination is nil")
	}

	// Verify config has default values
	defaultConfig := DefaultSessionConfig()
	if config.InboundTunnelLength != defaultConfig.InboundTunnelLength {
		t.Errorf("InboundTunnelLength = %d, want %d", config.InboundTunnelLength, defaultConfig.InboundTunnelLength)
	}
	if config.OutboundTunnelLength != defaultConfig.OutboundTunnelLength {
		t.Errorf("OutboundTunnelLength = %d, want %d", config.OutboundTunnelLength, defaultConfig.OutboundTunnelLength)
	}
	if config.InboundTunnelCount != defaultConfig.InboundTunnelCount {
		t.Errorf("InboundTunnelCount = %d, want %d", config.InboundTunnelCount, defaultConfig.InboundTunnelCount)
	}
	if config.OutboundTunnelCount != defaultConfig.OutboundTunnelCount {
		t.Errorf("OutboundTunnelCount = %d, want %d", config.OutboundTunnelCount, defaultConfig.OutboundTunnelCount)
	}
}

// TestParseCreateSessionPayload_CustomOptions tests parsing with custom tunnel configuration
func TestParseCreateSessionPayload_CustomOptions(t *testing.T) {
	// Create a test destination
	dest, err := createTestDestination()
	if err != nil {
		t.Fatalf("Failed to create test destination: %v", err)
	}

	destBytes, err := dest.Bytes()
	if err != nil {
		t.Fatalf("Failed to serialize destination: %v", err)
	}

	// Create options mapping with custom values
	options := map[string]string{
		"inbound.length":    "2", // 2 hops instead of default 3
		"outbound.length":   "4", // 4 hops instead of default 3
		"inbound.quantity":  "3", // 3 tunnels instead of default 5
		"outbound.quantity": "7", // 7 tunnels instead of default 5
		"inbound.nickname":  "test-session",
	}

	mapping, err := data.GoMapToMapping(options)
	if err != nil {
		t.Fatalf("Failed to create mapping: %v", err)
	}

	mappingBytes := mapping.Data()
	payload := append(destBytes, mappingBytes...)

	// Parse
	parsedDest, config, err := ParseCreateSessionPayload(payload)
	if err != nil {
		t.Fatalf("Failed to parse create session payload: %v", err)
	}

	// Verify destination
	if parsedDest == nil {
		t.Fatal("Parsed destination is nil")
	}

	// Verify custom config values
	if config.InboundTunnelLength != 2 {
		t.Errorf("InboundTunnelLength = %d, want 2", config.InboundTunnelLength)
	}
	if config.OutboundTunnelLength != 4 {
		t.Errorf("OutboundTunnelLength = %d, want 4", config.OutboundTunnelLength)
	}
	if config.InboundTunnelCount != 3 {
		t.Errorf("InboundTunnelCount = %d, want 3", config.InboundTunnelCount)
	}
	if config.OutboundTunnelCount != 7 {
		t.Errorf("OutboundTunnelCount = %d, want 7", config.OutboundTunnelCount)
	}
	if config.Nickname != "test-session" {
		t.Errorf("Nickname = %q, want %q", config.Nickname, "test-session")
	}
}

// TestParseCreateSessionPayload_InvalidOptions tests parsing with invalid option values
func TestParseCreateSessionPayload_InvalidOptions(t *testing.T) {
	dest, err := createTestDestination()
	if err != nil {
		t.Fatalf("Failed to create test destination: %v", err)
	}

	destBytes, err := dest.Bytes()
	if err != nil {
		t.Fatalf("Failed to serialize destination: %v", err)
	}

	// Create options with invalid values (should fall back to defaults)
	options := map[string]string{
		"inbound.length":    "99",           // Invalid (> 7)
		"outbound.length":   "-1",           // Invalid (< 0)
		"inbound.quantity":  "not_a_number", // Invalid
		"outbound.quantity": "0",            // Invalid (< 1)
	}

	mapping, err := data.GoMapToMapping(options)
	if err != nil {
		t.Fatalf("Failed to create mapping: %v", err)
	}

	payload := append(destBytes, mapping.Data()...)

	// Parse (should succeed with defaults)
	_, config, err := ParseCreateSessionPayload(payload)
	if err != nil {
		t.Fatalf("Failed to parse create session payload: %v", err)
	}

	// Verify fallback to defaults
	defaultConfig := DefaultSessionConfig()
	if config.InboundTunnelLength != defaultConfig.InboundTunnelLength {
		t.Errorf("InboundTunnelLength = %d, want default %d", config.InboundTunnelLength, defaultConfig.InboundTunnelLength)
	}
	if config.OutboundTunnelLength != defaultConfig.OutboundTunnelLength {
		t.Errorf("OutboundTunnelLength = %d, want default %d", config.OutboundTunnelLength, defaultConfig.OutboundTunnelLength)
	}
	if config.InboundTunnelCount != defaultConfig.InboundTunnelCount {
		t.Errorf("InboundTunnelCount = %d, want default %d", config.InboundTunnelCount, defaultConfig.InboundTunnelCount)
	}
	if config.OutboundTunnelCount != defaultConfig.OutboundTunnelCount {
		t.Errorf("OutboundTunnelCount = %d, want default %d", config.OutboundTunnelCount, defaultConfig.OutboundTunnelCount)
	}
}

// TestParseReconfigureSessionPayload tests parsing reconfiguration payloads
func TestParseReconfigureSessionPayload(t *testing.T) {
	// Create options mapping
	options := map[string]string{
		"inbound.length":    "1",
		"outbound.length":   "5",
		"inbound.quantity":  "2",
		"outbound.quantity": "8",
	}

	mapping, err := data.GoMapToMapping(options)
	if err != nil {
		t.Fatalf("Failed to create mapping: %v", err)
	}

	payload := mapping.Data()

	// Parse
	config, err := ParseReconfigureSessionPayload(payload)
	if err != nil {
		t.Fatalf("Failed to parse reconfigure session payload: %v", err)
	}

	// Verify values
	if config.InboundTunnelLength != 1 {
		t.Errorf("InboundTunnelLength = %d, want 1", config.InboundTunnelLength)
	}
	if config.OutboundTunnelLength != 5 {
		t.Errorf("OutboundTunnelLength = %d, want 5", config.OutboundTunnelLength)
	}
	if config.InboundTunnelCount != 2 {
		t.Errorf("InboundTunnelCount = %d, want 2", config.InboundTunnelCount)
	}
	if config.OutboundTunnelCount != 8 {
		t.Errorf("OutboundTunnelCount = %d, want 8", config.OutboundTunnelCount)
	}
}

// TestParseReconfigureSessionPayload_Empty tests error handling for empty payload
func TestParseReconfigureSessionPayload_Empty(t *testing.T) {
	_, err := ParseReconfigureSessionPayload([]byte{})
	if err == nil {
		t.Error("Expected error for empty payload, got nil")
	}

	_, err = ParseReconfigureSessionPayload([]byte{0x00})
	if err == nil {
		t.Error("Expected error for too short payload, got nil")
	}
}

// TestValidateSessionConfig tests session configuration validation
func TestValidateSessionConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *SessionConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name:    "valid default config",
			config:  DefaultSessionConfig(),
			wantErr: false,
		},
		{
			name: "invalid inbound length (too high)",
			config: &SessionConfig{
				InboundTunnelLength:  8, // Max is 7
				OutboundTunnelLength: 3,
				InboundTunnelCount:   5,
				OutboundTunnelCount:  5,
				TunnelLifetime:       10 * time.Minute,
				MessageQueueSize:     100,
			},
			wantErr: true,
		},
		{
			name: "invalid inbound length (negative)",
			config: &SessionConfig{
				InboundTunnelLength:  -1,
				OutboundTunnelLength: 3,
				InboundTunnelCount:   5,
				OutboundTunnelCount:  5,
				TunnelLifetime:       10 * time.Minute,
				MessageQueueSize:     100,
			},
			wantErr: true,
		},
		{
			name: "invalid tunnel count (zero)",
			config: &SessionConfig{
				InboundTunnelLength:  3,
				OutboundTunnelLength: 3,
				InboundTunnelCount:   0, // Must be >= 1
				OutboundTunnelCount:  5,
				TunnelLifetime:       10 * time.Minute,
				MessageQueueSize:     100,
			},
			wantErr: true,
		},
		{
			name: "invalid tunnel count (too high)",
			config: &SessionConfig{
				InboundTunnelLength:  3,
				OutboundTunnelLength: 3,
				InboundTunnelCount:   5,
				OutboundTunnelCount:  17, // Max is 16
				TunnelLifetime:       10 * time.Minute,
				MessageQueueSize:     100,
			},
			wantErr: true,
		},
		{
			name: "invalid tunnel lifetime (too short)",
			config: &SessionConfig{
				InboundTunnelLength:  3,
				OutboundTunnelLength: 3,
				InboundTunnelCount:   5,
				OutboundTunnelCount:  5,
				TunnelLifetime:       30 * time.Second, // Min is 1 minute
				MessageQueueSize:     100,
			},
			wantErr: true,
		},
		{
			name: "invalid tunnel lifetime (too long)",
			config: &SessionConfig{
				InboundTunnelLength:  3,
				OutboundTunnelLength: 3,
				InboundTunnelCount:   5,
				OutboundTunnelCount:  5,
				TunnelLifetime:       2 * time.Hour, // Max is 60 minutes
				MessageQueueSize:     100,
			},
			wantErr: true,
		},
		{
			name: "invalid message queue size",
			config: &SessionConfig{
				InboundTunnelLength:  3,
				OutboundTunnelLength: 3,
				InboundTunnelCount:   5,
				OutboundTunnelCount:  5,
				TunnelLifetime:       10 * time.Minute,
				MessageQueueSize:     0, // Must be >= 1
			},
			wantErr: true,
		},
		{
			name: "valid minimal config",
			config: &SessionConfig{
				InboundTunnelLength:  0, // 0-hop is valid (direct connection)
				OutboundTunnelLength: 1,
				InboundTunnelCount:   1,
				OutboundTunnelCount:  1,
				TunnelLifetime:       1 * time.Minute,
				MessageQueueSize:     1,
			},
			wantErr: false,
		},
		{
			name: "valid maximal config",
			config: &SessionConfig{
				InboundTunnelLength:  7,
				OutboundTunnelLength: 7,
				InboundTunnelCount:   16,
				OutboundTunnelCount:  16,
				TunnelLifetime:       60 * time.Minute,
				MessageQueueSize:     1000,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSessionConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSessionConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParseCreateSessionPayload_BoundaryValues tests edge cases for option values
func TestParseCreateSessionPayload_BoundaryValues(t *testing.T) {
	dest, err := createTestDestination()
	if err != nil {
		t.Fatalf("Failed to create test destination: %v", err)
	}

	destBytes, err := dest.Bytes()
	if err != nil {
		t.Fatalf("Failed to serialize destination: %v", err)
	}

	tests := []struct {
		name     string
		options  map[string]string
		validate func(*testing.T, *SessionConfig)
	}{
		{
			name: "minimum tunnel length",
			options: map[string]string{
				"inbound.length":  "0",
				"outbound.length": "0",
			},
			validate: func(t *testing.T, c *SessionConfig) {
				if c.InboundTunnelLength != 0 {
					t.Errorf("InboundTunnelLength = %d, want 0", c.InboundTunnelLength)
				}
				if c.OutboundTunnelLength != 0 {
					t.Errorf("OutboundTunnelLength = %d, want 0", c.OutboundTunnelLength)
				}
			},
		},
		{
			name: "maximum tunnel length",
			options: map[string]string{
				"inbound.length":  "7",
				"outbound.length": "7",
			},
			validate: func(t *testing.T, c *SessionConfig) {
				if c.InboundTunnelLength != 7 {
					t.Errorf("InboundTunnelLength = %d, want 7", c.InboundTunnelLength)
				}
				if c.OutboundTunnelLength != 7 {
					t.Errorf("OutboundTunnelLength = %d, want 7", c.OutboundTunnelLength)
				}
			},
		},
		{
			name: "minimum tunnel quantity",
			options: map[string]string{
				"inbound.quantity":  "1",
				"outbound.quantity": "1",
			},
			validate: func(t *testing.T, c *SessionConfig) {
				if c.InboundTunnelCount != 1 {
					t.Errorf("InboundTunnelCount = %d, want 1", c.InboundTunnelCount)
				}
				if c.OutboundTunnelCount != 1 {
					t.Errorf("OutboundTunnelCount = %d, want 1", c.OutboundTunnelCount)
				}
			},
		},
		{
			name: "maximum tunnel quantity",
			options: map[string]string{
				"inbound.quantity":  "16",
				"outbound.quantity": "16",
			},
			validate: func(t *testing.T, c *SessionConfig) {
				if c.InboundTunnelCount != 16 {
					t.Errorf("InboundTunnelCount = %d, want 16", c.InboundTunnelCount)
				}
				if c.OutboundTunnelCount != 16 {
					t.Errorf("OutboundTunnelCount = %d, want 16", c.OutboundTunnelCount)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapping, err := data.GoMapToMapping(tt.options)
			if err != nil {
				t.Fatalf("Failed to create mapping: %v", err)
			}

			payload := append(destBytes, mapping.Data()...)
			_, config, err := ParseCreateSessionPayload(payload)
			if err != nil {
				t.Fatalf("Failed to parse payload: %v", err)
			}

			tt.validate(t, config)
		})
	}
}

// TestApplyMessageOptions_Reliability tests that i2cp.messageReliability is wired into SessionConfig.
func TestApplyMessageOptions_Reliability(t *testing.T) {
	for _, rel := range []string{"BestEffort", "Guaranteed", "None"} {
		t.Run(rel, func(t *testing.T) {
			config := DefaultSessionConfig()
			options := map[string]string{"i2cp.messageReliability": rel}
			applyMessageOptions(config, options)
			if config.MessageReliability != rel {
				t.Errorf("MessageReliability = %q, want %q", config.MessageReliability, rel)
			}
			if !config.ExplicitlySetFields["MessageReliability"] {
				t.Error("MessageReliability not marked as explicitly set")
			}
		})
	}
	// Unknown value should keep default
	t.Run("unknown_value", func(t *testing.T) {
		config := DefaultSessionConfig()
		options := map[string]string{"i2cp.messageReliability": "Invalid"}
		applyMessageOptions(config, options)
		if config.MessageReliability != "BestEffort" {
			t.Errorf("MessageReliability = %q, want default BestEffort", config.MessageReliability)
		}
	})
}

// TestApplyMessageOptions_EncryptLeaseSet tests that i2cp.encryptLeaseSet enables UseEncryptedLeaseSet.
func TestApplyMessageOptions_EncryptLeaseSet(t *testing.T) {
	config := DefaultSessionConfig()
	if config.UseEncryptedLeaseSet {
		t.Fatal("UseEncryptedLeaseSet should default to false")
	}
	options := map[string]string{"i2cp.encryptLeaseSet": "true"}
	applyMessageOptions(config, options)
	if !config.UseEncryptedLeaseSet {
		t.Error("UseEncryptedLeaseSet should be true after setting i2cp.encryptLeaseSet=true")
	}
	if !config.ExplicitlySetFields["UseEncryptedLeaseSet"] {
		t.Error("UseEncryptedLeaseSet not marked as explicitly set")
	}
}

// TestApplyMessageOptions_DontPublishLeaseSet tests that i2cp.dontPublishLeaseSet is wired correctly.
func TestApplyMessageOptions_DontPublishLeaseSet(t *testing.T) {
	config := DefaultSessionConfig()
	if config.DontPublishLeaseSet {
		t.Fatal("DontPublishLeaseSet should default to false")
	}
	options := map[string]string{"i2cp.dontPublishLeaseSet": "true"}
	applyMessageOptions(config, options)
	if !config.DontPublishLeaseSet {
		t.Error("DontPublishLeaseSet should be true after setting i2cp.dontPublishLeaseSet=true")
	}
	if !config.ExplicitlySetFields["DontPublishLeaseSet"] {
		t.Error("DontPublishLeaseSet not marked as explicitly set")
	}
}

// TestApplyMessageOptions_GzipStillUnsupported verifies i2cp.gzip is tracked as unsupported.
func TestApplyMessageOptions_GzipStillUnsupported(t *testing.T) {
	config := DefaultSessionConfig()
	options := map[string]string{"i2cp.gzip": "true"}
	applyMessageOptions(config, options)
	if val, ok := config.UnsupportedOptions["i2cp.gzip"]; !ok || val != "true" {
		t.Errorf("i2cp.gzip should be recorded in UnsupportedOptions, got %v", config.UnsupportedOptions)
	}
}

// TestLogUnsupportedBackupQuantities_AppliesValues tests that backup quantities are stored.
func TestLogUnsupportedBackupQuantities_AppliesValues(t *testing.T) {
	config := DefaultSessionConfig()
	options := map[string]string{
		"inbound.backupQuantity":  "2",
		"outbound.backupQuantity": "3",
	}
	logUnsupportedBackupQuantities(config, options)
	if config.InboundBackupQuantity != 2 {
		t.Errorf("InboundBackupQuantity = %d, want 2", config.InboundBackupQuantity)
	}
	if config.OutboundBackupQuantity != 3 {
		t.Errorf("OutboundBackupQuantity = %d, want 3", config.OutboundBackupQuantity)
	}
	if !config.ExplicitlySetFields["InboundBackupQuantity"] {
		t.Error("InboundBackupQuantity not marked as explicitly set")
	}
	if !config.ExplicitlySetFields["OutboundBackupQuantity"] {
		t.Error("OutboundBackupQuantity not marked as explicitly set")
	}
}

// TestLogUnsupportedBackupQuantities_OutOfRange tests that out-of-range values are ignored.
func TestLogUnsupportedBackupQuantities_OutOfRange(t *testing.T) {
	config := DefaultSessionConfig()
	options := map[string]string{
		"inbound.backupQuantity":  "-1",
		"outbound.backupQuantity": "17",
	}
	logUnsupportedBackupQuantities(config, options)
	if config.InboundBackupQuantity != 0 {
		t.Errorf("InboundBackupQuantity = %d, want 0 (default for out-of-range)", config.InboundBackupQuantity)
	}
	if config.OutboundBackupQuantity != 0 {
		t.Errorf("OutboundBackupQuantity = %d, want 0 (default for out-of-range)", config.OutboundBackupQuantity)
	}
}

// TestApplyTunnelLifetimeOptions_AppliesVariance tests that length variance is stored.
func TestApplyTunnelLifetimeOptions_AppliesVariance(t *testing.T) {
	config := DefaultSessionConfig()
	options := map[string]string{
		"inbound.lengthVariance":  "-1",
		"outbound.lengthVariance": "2",
	}
	applyTunnelLifetimeOptions(config, options)
	if config.InboundLengthVariance != -1 {
		t.Errorf("InboundLengthVariance = %d, want -1", config.InboundLengthVariance)
	}
	if config.OutboundLengthVariance != 2 {
		t.Errorf("OutboundLengthVariance = %d, want 2", config.OutboundLengthVariance)
	}
	if !config.ExplicitlySetFields["InboundLengthVariance"] {
		t.Error("InboundLengthVariance not marked as explicitly set")
	}
	if !config.ExplicitlySetFields["OutboundLengthVariance"] {
		t.Error("OutboundLengthVariance not marked as explicitly set")
	}
}

// TestApplyTunnelLifetimeOptions_OutOfRange tests that out-of-range variance values are ignored.
func TestApplyTunnelLifetimeOptions_OutOfRange(t *testing.T) {
	config := DefaultSessionConfig()
	options := map[string]string{
		"inbound.lengthVariance":  "-8",
		"outbound.lengthVariance": "8",
	}
	applyTunnelLifetimeOptions(config, options)
	if config.InboundLengthVariance != 0 {
		t.Errorf("InboundLengthVariance = %d, want 0 (default for out-of-range)", config.InboundLengthVariance)
	}
	if config.OutboundLengthVariance != 0 {
		t.Errorf("OutboundLengthVariance = %d, want 0 (default for out-of-range)", config.OutboundLengthVariance)
	}
}

// TestFullParsePipeline_NewOptions tests end-to-end parsing of the newly implemented options
// through the full CreateSession payload parsing pipeline.
func TestFullParsePipeline_NewOptions(t *testing.T) {
	dest, err := createTestDestination()
	if err != nil {
		t.Fatalf("Failed to create test destination: %v", err)
	}
	destBytes, err := dest.Bytes()
	if err != nil {
		t.Fatalf("Failed to serialize destination: %v", err)
	}

	options := map[string]string{
		"inbound.length":           "3",
		"outbound.length":          "3",
		"inbound.quantity":         "5",
		"outbound.quantity":        "5",
		"inbound.backupQuantity":   "1",
		"outbound.backupQuantity":  "2",
		"inbound.lengthVariance":   "-1",
		"outbound.lengthVariance":  "3",
		"i2cp.messageReliability":  "Guaranteed",
		"i2cp.encryptLeaseSet":     "true",
		"i2cp.dontPublishLeaseSet": "true",
	}

	mapping, err := data.GoMapToMapping(options)
	if err != nil {
		t.Fatalf("Failed to create mapping: %v", err)
	}

	payload := append(destBytes, mapping.Data()...)
	_, config, err := ParseCreateSessionPayload(payload)
	if err != nil {
		t.Fatalf("Failed to parse payload: %v", err)
	}

	// Verify all newly-wired options
	if config.InboundBackupQuantity != 1 {
		t.Errorf("InboundBackupQuantity = %d, want 1", config.InboundBackupQuantity)
	}
	if config.OutboundBackupQuantity != 2 {
		t.Errorf("OutboundBackupQuantity = %d, want 2", config.OutboundBackupQuantity)
	}
	if config.InboundLengthVariance != -1 {
		t.Errorf("InboundLengthVariance = %d, want -1", config.InboundLengthVariance)
	}
	if config.OutboundLengthVariance != 3 {
		t.Errorf("OutboundLengthVariance = %d, want 3", config.OutboundLengthVariance)
	}
	if config.MessageReliability != "Guaranteed" {
		t.Errorf("MessageReliability = %q, want Guaranteed", config.MessageReliability)
	}
	if !config.UseEncryptedLeaseSet {
		t.Error("UseEncryptedLeaseSet should be true")
	}
	if !config.DontPublishLeaseSet {
		t.Error("DontPublishLeaseSet should be true")
	}

	// i2cp.encryptLeaseSet should NOT appear in UnsupportedOptions anymore
	if _, exists := config.UnsupportedOptions["i2cp.encryptLeaseSet"]; exists {
		t.Error("i2cp.encryptLeaseSet should not be in UnsupportedOptions after being wired")
	}
	if _, exists := config.UnsupportedOptions["i2cp.messageReliability"]; exists {
		t.Error("i2cp.messageReliability should not be in UnsupportedOptions after being wired")
	}
}
