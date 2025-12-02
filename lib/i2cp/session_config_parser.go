package i2cp

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/logger"
)

// SessionConfigParser parses I2CP CreateSession and ReconfigureSession message payloads.
// These messages contain a Destination followed by session options (Mapping).
//
// Payload format (CreateSession):
//   - Destination (variable length)
//   - Options (Mapping - key/value pairs)
//
// Payload format (ReconfigureSession):
//   - SessionID (2 bytes) - already in message header
//   - Options (Mapping - key/value pairs)
//
// Standard I2CP option keys (from Java I2P):
//   - inbound.length: Number of hops for inbound tunnels (default: 3)
//   - outbound.length: Number of hops for outbound tunnels (default: 3)
//   - inbound.quantity: Number of inbound tunnels (default: 5)
//   - outbound.quantity: Number of outbound tunnels (default: 5)
//   - i2cp.messageReliability: Message reliability (default: BestEffort)
//   - i2cp.encryptLeaseSet: Encrypt LeaseSet (default: false)
//
// Note: Most options use standard library strconv for parsing integers.
// Returns DefaultSessionConfig values for unspecified options.

// ParseCreateSessionPayload parses a CreateSession message payload.
// Returns the destination and session configuration.
//
// Wire format:
//   - Destination (variable length, typically ~387+ bytes)
//   - Options Mapping (2-byte size + key=value; pairs)
func ParseCreateSessionPayload(payload []byte) (*destination.Destination, *SessionConfig, error) {
	if len(payload) < 2 {
		return nil, nil, fmt.Errorf("create session payload too short: %d bytes", len(payload))
	}

	// Parse destination (reads variable-length structure)
	dest, remainingBytes, err := parseDestination(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse destination: %w", err)
	}

	// Parse options mapping from remaining bytes
	config, err := parseSessionOptions(remainingBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse session options: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":                     "i2cp.ParseCreateSessionPayload",
		"inbound_tunnel_length":  config.InboundTunnelLength,
		"outbound_tunnel_length": config.OutboundTunnelLength,
		"inbound_tunnel_count":   config.InboundTunnelCount,
		"outbound_tunnel_count":  config.OutboundTunnelCount,
	}).Debug("parsed_create_session_payload")

	return dest, config, nil
}

// ParseReconfigureSessionPayload parses a ReconfigureSession message payload.
// Returns the updated session configuration.
//
// Wire format:
//   - Options Mapping (2-byte size + key=value; pairs)
//
// Note: SessionID is in the message header, not the payload.
func ParseReconfigureSessionPayload(payload []byte) (*SessionConfig, error) {
	if len(payload) < 2 {
		return nil, fmt.Errorf("reconfigure session payload too short: %d bytes", len(payload))
	}

	// Parse options mapping
	config, err := parseSessionOptions(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse session options: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":                     "i2cp.ParseReconfigureSessionPayload",
		"inbound_tunnel_length":  config.InboundTunnelLength,
		"outbound_tunnel_length": config.OutboundTunnelLength,
		"inbound_tunnel_count":   config.InboundTunnelCount,
		"outbound_tunnel_count":  config.OutboundTunnelCount,
	}).Debug("parsed_reconfigure_session_payload")

	return config, nil
}

// parseDestination extracts an I2P Destination from the payload.
// Returns the destination and remaining bytes after the destination.
func parseDestination(payload []byte) (*destination.Destination, []byte, error) {
	dest, remaining, err := destination.ReadDestination(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read destination: %w", err)
	}

	return &dest, remaining, nil
}

// parseSessionOptions parses an I2CP session options Mapping and converts it to SessionConfig.
// Uses DefaultSessionConfig as baseline and overrides with provided options.
func parseSessionOptions(optionsBytes []byte) (*SessionConfig, error) {
	// Start with defaults
	config := DefaultSessionConfig()

	// Handle empty or minimal options (less than 3 bytes can't be a valid mapping)
	if len(optionsBytes) < 3 {
		log.Debug("No session options or invalid mapping provided, using defaults")
		return config, nil
	}

	// Parse options mapping
	mapping, _, errs := data.ReadMapping(optionsBytes)
	if len(errs) > 0 {
		// If mapping can't be parsed, log warning but return defaults
		log.WithField("errors", errs).Warn("Failed to parse options mapping, using defaults")
		return config, nil
	}

	// Convert mapping to Go map for easier access
	optionsMap := mappingToGoMap(mapping)

	// Apply options to config
	applyTunnelLengthOptions(config, optionsMap)
	applyTunnelQuantityOptions(config, optionsMap)
	applyTunnelLifetimeOptions(config, optionsMap)
	applyMessageOptions(config, optionsMap)
	applyMetadataOptions(config, optionsMap)

	return config, nil
}

// mappingToGoMap converts an I2P Mapping to a Go map[string]string.
func mappingToGoMap(mapping data.Mapping) map[string]string {
	result := make(map[string]string)
	values := mapping.Values()

	for _, pair := range values {
		if len(pair) != 2 {
			log.WithField("pair_length", len(pair)).Warn("invalid mapping pair")
			continue
		}

		key, keyErr := pair[0].Data()
		value, valErr := pair[1].Data()

		if keyErr != nil || valErr != nil {
			log.WithFields(logger.Fields{
				"key_error":   keyErr,
				"value_error": valErr,
			}).Warn("failed to extract mapping pair")
			continue
		}

		result[key] = value
	}

	return result
}

// applyTunnelLengthOptions applies tunnel length configuration options.
// Keys: inbound.length, outbound.length
func applyTunnelLengthOptions(config *SessionConfig, options map[string]string) {
	if val, exists := options["inbound.length"]; exists {
		if length, err := strconv.Atoi(val); err == nil && length >= 0 && length <= 7 {
			config.InboundTunnelLength = length
		} else {
			log.WithFields(logger.Fields{
				"value": val,
				"error": err,
			}).Warn("invalid inbound.length option, using default")
		}
	}

	if val, exists := options["outbound.length"]; exists {
		if length, err := strconv.Atoi(val); err == nil && length >= 0 && length <= 7 {
			config.OutboundTunnelLength = length
		} else {
			log.WithFields(logger.Fields{
				"value": val,
				"error": err,
			}).Warn("invalid outbound.length option, using default")
		}
	}
}

// applyTunnelQuantityOptions applies tunnel quantity configuration options.
// Keys: inbound.quantity, outbound.quantity, inbound.backupQuantity, outbound.backupQuantity
func applyTunnelQuantityOptions(config *SessionConfig, options map[string]string) {
	if val, exists := options["inbound.quantity"]; exists {
		if quantity, err := strconv.Atoi(val); err == nil && quantity >= 1 && quantity <= 16 {
			config.InboundTunnelCount = quantity
		} else {
			log.WithFields(logger.Fields{
				"value": val,
				"error": err,
			}).Warn("invalid inbound.quantity option, using default")
		}
	}

	if val, exists := options["outbound.quantity"]; exists {
		if quantity, err := strconv.Atoi(val); err == nil && quantity >= 1 && quantity <= 16 {
			config.OutboundTunnelCount = quantity
		} else {
			log.WithFields(logger.Fields{
				"value": val,
				"error": err,
			}).Warn("invalid outbound.quantity option, using default")
		}
	}

	// Note: backup quantities not currently implemented in SessionConfig
	// They would be used for tunnel pool redundancy
}

// applyTunnelLifetimeOptions applies tunnel lifetime configuration options.
// Keys: inbound.lengthVariance, outbound.lengthVariance (affects lifetime calculation)
//
// Note: Java I2P doesn't have a direct "tunnel.lifetime" option.
// Lifetime is calculated based on tunnel properties and network conditions.
// We keep the default and may adjust in future based on variance settings.
func applyTunnelLifetimeOptions(config *SessionConfig, options map[string]string) {
	// Currently no direct lifetime option in I2CP
	// Java I2P uses fixed 10-minute lifetime with some variance
	// Keep default for now
}

// applyMessageOptions applies message-related configuration options.
// Keys: i2cp.messageReliability, i2cp.gzip
func applyMessageOptions(config *SessionConfig, options map[string]string) {
	// Message reliability and compression not yet implemented in SessionConfig
	// These would affect message delivery guarantees and payload compression
	// Currently all messages use best-effort delivery
}

// applyMetadataOptions applies metadata configuration options.
// Keys: inbound.nickname, outbound.nickname (for debugging)
func applyMetadataOptions(config *SessionConfig, options map[string]string) {
	// Check for nickname option (common in Java I2P clients)
	if val, exists := options["inbound.nickname"]; exists {
		config.Nickname = val
	} else if val, exists := options["outbound.nickname"]; exists {
		config.Nickname = val
	}
}

// ValidateSessionConfig validates session configuration values are within acceptable ranges.
// Returns error if validation fails.
func ValidateSessionConfig(config *SessionConfig) error {
	if config == nil {
		return fmt.Errorf("session config is nil")
	}

	if err := validateTunnelLengths(config); err != nil {
		return err
	}

	if err := validateTunnelCounts(config); err != nil {
		return err
	}

	if err := validateTunnelLifetime(config); err != nil {
		return err
	}

	if err := validateMessageQueueSize(config); err != nil {
		return err
	}

	return nil
}

// validateTunnelLengths validates inbound and outbound tunnel length are within I2P spec limits (0-7 hops).
// Returns error if either tunnel length is out of range.
func validateTunnelLengths(config *SessionConfig) error {
	if config.InboundTunnelLength < 0 || config.InboundTunnelLength > 7 {
		return fmt.Errorf("invalid inbound tunnel length: %d (must be 0-7)", config.InboundTunnelLength)
	}
	if config.OutboundTunnelLength < 0 || config.OutboundTunnelLength > 7 {
		return fmt.Errorf("invalid outbound tunnel length: %d (must be 0-7)", config.OutboundTunnelLength)
	}
	return nil
}

// validateTunnelCounts validates inbound and outbound tunnel counts are within reasonable limits (1-16).
// Returns error if either tunnel count is out of range.
func validateTunnelCounts(config *SessionConfig) error {
	if config.InboundTunnelCount < 1 || config.InboundTunnelCount > 16 {
		return fmt.Errorf("invalid inbound tunnel count: %d (must be 1-16)", config.InboundTunnelCount)
	}
	if config.OutboundTunnelCount < 1 || config.OutboundTunnelCount > 16 {
		return fmt.Errorf("invalid outbound tunnel count: %d (must be 1-16)", config.OutboundTunnelCount)
	}
	return nil
}

// validateTunnelLifetime validates tunnel lifetime is within reasonable bounds (1 minute to 1 hour).
// Returns error if lifetime is out of range.
func validateTunnelLifetime(config *SessionConfig) error {
	if config.TunnelLifetime < 1*time.Minute || config.TunnelLifetime > 60*time.Minute {
		return fmt.Errorf("invalid tunnel lifetime: %v (must be 1m-60m)", config.TunnelLifetime)
	}
	return nil
}

// validateMessageQueueSize validates message queue size is positive.
// Returns error if queue size is less than 1.
func validateMessageQueueSize(config *SessionConfig) error {
	if config.MessageQueueSize < 1 {
		return fmt.Errorf("invalid message queue size: %d (must be >= 1)", config.MessageQueueSize)
	}
	return nil
}
