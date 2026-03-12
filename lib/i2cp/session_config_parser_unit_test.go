package i2cp

import (
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseCreateSessionPayload_Empty tests parsing with empty/minimal payload
func TestParseCreateSessionPayload_Empty(t *testing.T) {
	_, _, err := ParseCreateSessionPayload([]byte{})
	assert.Error(t, err, "Expected error for empty payload")

	_, _, err = ParseCreateSessionPayload([]byte{0x01})
	assert.Error(t, err, "Expected error for too short payload")
}

// TestParseCreateSessionPayload_DefaultOptions tests parsing with default options (empty mapping)
func TestParseCreateSessionPayload_DefaultOptions(t *testing.T) {
	dest, err := createTestDestination()
	require.NoError(t, err, "Failed to create test destination")

	destBytes, err := dest.Bytes()
	require.NoError(t, err, "Failed to serialize destination")

	// Create empty options mapping - just 2 bytes for size=0
	mappingBytes := []byte{0x00, 0x00}
	payload := append(destBytes, mappingBytes...)

	parsedDest, config, err := ParseCreateSessionPayload(payload)
	require.NoError(t, err, "Failed to parse create session payload")
	require.NotNil(t, parsedDest, "Parsed destination is nil")

	defaultConfig := DefaultSessionConfig()
	assert.Equal(t, defaultConfig.InboundTunnelLength, config.InboundTunnelLength, "InboundTunnelLength")
	assert.Equal(t, defaultConfig.OutboundTunnelLength, config.OutboundTunnelLength, "OutboundTunnelLength")
	assert.Equal(t, defaultConfig.InboundTunnelCount, config.InboundTunnelCount, "InboundTunnelCount")
	assert.Equal(t, defaultConfig.OutboundTunnelCount, config.OutboundTunnelCount, "OutboundTunnelCount")
}

// TestParseCreateSessionPayload_CustomOptions tests parsing with custom tunnel configuration
func TestParseCreateSessionPayload_CustomOptions(t *testing.T) {
	dest, err := createTestDestination()
	require.NoError(t, err, "Failed to create test destination")

	destBytes, err := dest.Bytes()
	require.NoError(t, err, "Failed to serialize destination")

	options := map[string]string{
		"inbound.length":    "2",
		"outbound.length":   "4",
		"inbound.quantity":  "3",
		"outbound.quantity": "7",
		"inbound.nickname":  "test-session",
	}

	mapping, err := data.GoMapToMapping(options)
	require.NoError(t, err, "Failed to create mapping")

	mappingBytes := mapping.Data()
	payload := append(destBytes, mappingBytes...)

	parsedDest, config, err := ParseCreateSessionPayload(payload)
	require.NoError(t, err, "Failed to parse create session payload")
	require.NotNil(t, parsedDest, "Parsed destination is nil")

	assert.Equal(t, 2, config.InboundTunnelLength, "InboundTunnelLength")
	assert.Equal(t, 4, config.OutboundTunnelLength, "OutboundTunnelLength")
	assert.Equal(t, 3, config.InboundTunnelCount, "InboundTunnelCount")
	assert.Equal(t, 7, config.OutboundTunnelCount, "OutboundTunnelCount")
	assert.Equal(t, "test-session", config.Nickname, "Nickname")
}

// TestParseCreateSessionPayload_InvalidOptions tests parsing with invalid option values
func TestParseCreateSessionPayload_InvalidOptions(t *testing.T) {
	dest, err := createTestDestination()
	require.NoError(t, err, "Failed to create test destination")

	destBytes, err := dest.Bytes()
	require.NoError(t, err, "Failed to serialize destination")

	options := map[string]string{
		"inbound.length":    "99",
		"outbound.length":   "-1",
		"inbound.quantity":  "not_a_number",
		"outbound.quantity": "0",
	}

	mapping, err := data.GoMapToMapping(options)
	require.NoError(t, err, "Failed to create mapping")

	payload := append(destBytes, mapping.Data()...)

	_, config, err := ParseCreateSessionPayload(payload)
	require.NoError(t, err, "Failed to parse create session payload")

	defaultConfig := DefaultSessionConfig()
	assert.Equal(t, defaultConfig.InboundTunnelLength, config.InboundTunnelLength, "InboundTunnelLength")
	assert.Equal(t, defaultConfig.OutboundTunnelLength, config.OutboundTunnelLength, "OutboundTunnelLength")
	assert.Equal(t, defaultConfig.InboundTunnelCount, config.InboundTunnelCount, "InboundTunnelCount")
	assert.Equal(t, defaultConfig.OutboundTunnelCount, config.OutboundTunnelCount, "OutboundTunnelCount")
}

// TestParseReconfigureSessionPayload tests parsing reconfiguration payloads
func TestParseReconfigureSessionPayload(t *testing.T) {
	options := map[string]string{
		"inbound.length":    "1",
		"outbound.length":   "5",
		"inbound.quantity":  "2",
		"outbound.quantity": "8",
	}

	mapping, err := data.GoMapToMapping(options)
	require.NoError(t, err, "Failed to create mapping")

	config, err := ParseReconfigureSessionPayload(mapping.Data())
	require.NoError(t, err, "Failed to parse reconfigure session payload")

	assert.Equal(t, 1, config.InboundTunnelLength, "InboundTunnelLength")
	assert.Equal(t, 5, config.OutboundTunnelLength, "OutboundTunnelLength")
	assert.Equal(t, 2, config.InboundTunnelCount, "InboundTunnelCount")
	assert.Equal(t, 8, config.OutboundTunnelCount, "OutboundTunnelCount")
}

// TestParseReconfigureSessionPayload_Empty tests error handling for empty payload
func TestParseReconfigureSessionPayload_Empty(t *testing.T) {
	_, err := ParseReconfigureSessionPayload([]byte{})
	assert.Error(t, err, "Expected error for empty payload")

	_, err = ParseReconfigureSessionPayload([]byte{0x00})
	assert.Error(t, err, "Expected error for too short payload")
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
	require.NoError(t, err, "Failed to create test destination")

	destBytes, err := dest.Bytes()
	require.NoError(t, err, "Failed to serialize destination")

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
				assert.Equal(t, 0, c.InboundTunnelLength, "InboundTunnelLength")
				assert.Equal(t, 0, c.OutboundTunnelLength, "OutboundTunnelLength")
			},
		},
		{
			name: "maximum tunnel length",
			options: map[string]string{
				"inbound.length":  "7",
				"outbound.length": "7",
			},
			validate: func(t *testing.T, c *SessionConfig) {
				assert.Equal(t, 7, c.InboundTunnelLength, "InboundTunnelLength")
				assert.Equal(t, 7, c.OutboundTunnelLength, "OutboundTunnelLength")
			},
		},
		{
			name: "minimum tunnel quantity",
			options: map[string]string{
				"inbound.quantity":  "1",
				"outbound.quantity": "1",
			},
			validate: func(t *testing.T, c *SessionConfig) {
				assert.Equal(t, 1, c.InboundTunnelCount, "InboundTunnelCount")
				assert.Equal(t, 1, c.OutboundTunnelCount, "OutboundTunnelCount")
			},
		},
		{
			name: "maximum tunnel quantity",
			options: map[string]string{
				"inbound.quantity":  "16",
				"outbound.quantity": "16",
			},
			validate: func(t *testing.T, c *SessionConfig) {
				assert.Equal(t, 16, c.InboundTunnelCount, "InboundTunnelCount")
				assert.Equal(t, 16, c.OutboundTunnelCount, "OutboundTunnelCount")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapping, err := data.GoMapToMapping(tt.options)
			require.NoError(t, err, "Failed to create mapping")

			payload := append(destBytes, mapping.Data()...)
			_, config, err := ParseCreateSessionPayload(payload)
			require.NoError(t, err, "Failed to parse payload")

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
			assert.Equal(t, rel, config.MessageReliability, "MessageReliability")
			assert.True(t, config.ExplicitlySetFields["MessageReliability"], "MessageReliability not marked as explicitly set")
		})
	}
	t.Run("unknown_value", func(t *testing.T) {
		config := DefaultSessionConfig()
		options := map[string]string{"i2cp.messageReliability": "Invalid"}
		applyMessageOptions(config, options)
		assert.Equal(t, "BestEffort", config.MessageReliability, "MessageReliability")
	})
}

// TestApplyMessageOptions_EncryptLeaseSet tests that i2cp.encryptLeaseSet enables UseEncryptedLeaseSet.
func TestApplyMessageOptions_EncryptLeaseSet(t *testing.T) {
	config := DefaultSessionConfig()
	require.False(t, config.UseEncryptedLeaseSet, "UseEncryptedLeaseSet should default to false")
	options := map[string]string{"i2cp.encryptLeaseSet": "true"}
	applyMessageOptions(config, options)
	assert.True(t, config.UseEncryptedLeaseSet, "UseEncryptedLeaseSet should be true")
	assert.True(t, config.ExplicitlySetFields["UseEncryptedLeaseSet"], "not marked as explicitly set")
}

// TestApplyMessageOptions_DontPublishLeaseSet tests that i2cp.dontPublishLeaseSet is wired correctly.
func TestApplyMessageOptions_DontPublishLeaseSet(t *testing.T) {
	config := DefaultSessionConfig()
	require.False(t, config.DontPublishLeaseSet, "DontPublishLeaseSet should default to false")
	options := map[string]string{"i2cp.dontPublishLeaseSet": "true"}
	applyMessageOptions(config, options)
	assert.True(t, config.DontPublishLeaseSet, "DontPublishLeaseSet should be true")
	assert.True(t, config.ExplicitlySetFields["DontPublishLeaseSet"], "not marked as explicitly set")
}

// TestApplyMessageOptions_GzipStillUnsupported verifies i2cp.gzip is tracked as unsupported.
func TestApplyMessageOptions_GzipStillUnsupported(t *testing.T) {
	config := DefaultSessionConfig()
	options := map[string]string{"i2cp.gzip": "true"}
	applyMessageOptions(config, options)
	assert.Equal(t, "true", config.UnsupportedOptions["i2cp.gzip"], "i2cp.gzip should be recorded in UnsupportedOptions")
}

// TestLogUnsupportedBackupQuantities_AppliesValues tests that backup quantities are stored.
func TestLogUnsupportedBackupQuantities_AppliesValues(t *testing.T) {
	config := DefaultSessionConfig()
	options := map[string]string{
		"inbound.backupQuantity":  "2",
		"outbound.backupQuantity": "3",
	}
	logUnsupportedBackupQuantities(config, options)
	assert.Equal(t, 2, config.InboundBackupQuantity, "InboundBackupQuantity")
	assert.Equal(t, 3, config.OutboundBackupQuantity, "OutboundBackupQuantity")
	assert.True(t, config.ExplicitlySetFields["InboundBackupQuantity"], "InboundBackupQuantity not marked")
	assert.True(t, config.ExplicitlySetFields["OutboundBackupQuantity"], "OutboundBackupQuantity not marked")
}

// TestLogUnsupportedBackupQuantities_OutOfRange tests that out-of-range values are ignored.
func TestLogUnsupportedBackupQuantities_OutOfRange(t *testing.T) {
	config := DefaultSessionConfig()
	options := map[string]string{
		"inbound.backupQuantity":  "-1",
		"outbound.backupQuantity": "17",
	}
	logUnsupportedBackupQuantities(config, options)
	assert.Equal(t, 0, config.InboundBackupQuantity, "InboundBackupQuantity")
	assert.Equal(t, 0, config.OutboundBackupQuantity, "OutboundBackupQuantity")
}

// TestApplyTunnelLifetimeOptions_AppliesVariance tests that length variance is stored.
func TestApplyTunnelLifetimeOptions_AppliesVariance(t *testing.T) {
	config := DefaultSessionConfig()
	options := map[string]string{
		"inbound.lengthVariance":  "-1",
		"outbound.lengthVariance": "2",
	}
	applyTunnelLifetimeOptions(config, options)
	assert.Equal(t, -1, config.InboundLengthVariance, "InboundLengthVariance")
	assert.Equal(t, 2, config.OutboundLengthVariance, "OutboundLengthVariance")
	assert.True(t, config.ExplicitlySetFields["InboundLengthVariance"], "InboundLengthVariance not marked")
	assert.True(t, config.ExplicitlySetFields["OutboundLengthVariance"], "OutboundLengthVariance not marked")
}

// TestApplyTunnelLifetimeOptions_OutOfRange tests that out-of-range variance values are ignored.
func TestApplyTunnelLifetimeOptions_OutOfRange(t *testing.T) {
	config := DefaultSessionConfig()
	options := map[string]string{
		"inbound.lengthVariance":  "-8",
		"outbound.lengthVariance": "8",
	}
	applyTunnelLifetimeOptions(config, options)
	assert.Equal(t, 0, config.InboundLengthVariance, "InboundLengthVariance")
	assert.Equal(t, 0, config.OutboundLengthVariance, "OutboundLengthVariance")
}

// TestFullParsePipeline_NewOptions tests end-to-end parsing of the newly implemented options
// through the full CreateSession payload parsing pipeline.
func TestFullParsePipeline_NewOptions(t *testing.T) {
	dest, err := createTestDestination()
	require.NoError(t, err, "Failed to create test destination")
	destBytes, err := dest.Bytes()
	require.NoError(t, err, "Failed to serialize destination")

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
	require.NoError(t, err, "Failed to create mapping")

	payload := append(destBytes, mapping.Data()...)
	_, config, err := ParseCreateSessionPayload(payload)
	require.NoError(t, err, "Failed to parse payload")

	assert.Equal(t, 1, config.InboundBackupQuantity, "InboundBackupQuantity")
	assert.Equal(t, 2, config.OutboundBackupQuantity, "OutboundBackupQuantity")
	assert.Equal(t, -1, config.InboundLengthVariance, "InboundLengthVariance")
	assert.Equal(t, 3, config.OutboundLengthVariance, "OutboundLengthVariance")
	assert.Equal(t, "Guaranteed", config.MessageReliability, "MessageReliability")
	assert.True(t, config.UseEncryptedLeaseSet, "UseEncryptedLeaseSet should be true")
	assert.True(t, config.DontPublishLeaseSet, "DontPublishLeaseSet should be true")

	assert.NotContains(t, config.UnsupportedOptions, "i2cp.encryptLeaseSet")
	assert.NotContains(t, config.UnsupportedOptions, "i2cp.messageReliability")
}
