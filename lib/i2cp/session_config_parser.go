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
	// i2psnark compatibility: Log payload size for debugging
	log.WithFields(logger.Fields{
		"at":          "i2cp.ParseCreateSessionPayload",
		"payloadSize": len(payload),
	}).Debug("parsing_create_session_payload")

	if len(payload) < 2 {
		log.WithFields(logger.Fields{
			"at":          "i2cp.ParseCreateSessionPayload",
			"payloadSize": len(payload),
			"required":    2,
		}).Error("create_session_payload_too_short")
		return nil, nil, fmt.Errorf("create session payload too short: %d bytes", len(payload))
	}

	// Parse destination (reads variable-length structure)
	dest, remainingBytes, err := parseDestination(payload)
	if err != nil {
		// i2psnark compatibility: Log destination parsing failure with excerpt
		excerptLen := 64
		if len(payload) < excerptLen {
			excerptLen = len(payload)
		}
		log.WithFields(logger.Fields{
			"at":             "i2cp.ParseCreateSessionPayload",
			"error":          err.Error(),
			"payloadSize":    len(payload),
			"payloadExcerpt": fmt.Sprintf("%x", payload[:excerptLen]),
		}).Error("failed_to_parse_destination")
		return nil, nil, fmt.Errorf("failed to parse destination: %w", err)
	}

	// Parse options mapping from remaining bytes
	log.WithFields(logger.Fields{
		"at":             "i2cp.ParseCreateSessionPayload",
		"remainingBytes": len(remainingBytes),
	}).Debug("parsing_session_options")

	config, err := parseSessionOptions(remainingBytes)
	if err != nil {
		// i2psnark compatibility: Log options parsing failure
		log.WithFields(logger.Fields{
			"at":             "i2cp.ParseCreateSessionPayload",
			"error":          err.Error(),
			"remainingBytes": len(remainingBytes),
		}).Error("failed_to_parse_session_options")
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
		log.WithFields(logger.Fields{
			"at":          "i2cp.parseDestination",
			"payloadSize": len(payload),
			"error":       err.Error(),
		}).Error("failed_to_read_destination")
		return nil, nil, fmt.Errorf("failed to read destination: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":            "i2cp.parseDestination",
		"destSize":      len(payload) - len(remaining),
		"remainingSize": len(remaining),
	}).Debug("destination_parsed")

	return &dest, remaining, nil
}

// parseSessionOptions parses an I2CP session options Mapping and converts it to SessionConfig.
// Uses DefaultSessionConfig as baseline and overrides with provided options.
func parseSessionOptions(optionsBytes []byte) (*SessionConfig, error) {
	// Start with defaults
	config := DefaultSessionConfig()

	// Handle empty or minimal options (less than 3 bytes can't be a valid mapping)
	if len(optionsBytes) < 3 {
		log.WithFields(logger.Fields{
			"at":         "i2cp.parseSessionOptions",
			"optionSize": len(optionsBytes),
		}).Debug("no_session_options_using_defaults")
		return config, nil
	}

	// Parse options mapping
	mapping, _, errs := data.ReadMapping(optionsBytes)
	if len(errs) > 0 {
		// If mapping can't be parsed, return an error so the client is aware
		// of the misconfiguration rather than silently using defaults.
		log.WithFields(logger.Fields{
			"at":     "i2cp.parseSessionOptions",
			"errors": fmt.Sprintf("%v", errs),
		}).Warn("failed_to_parse_options_mapping")
		return nil, fmt.Errorf("failed to parse session options mapping: %v", errs)
	}

	// Convert mapping to Go map for easier access
	optionsMap := mappingToGoMap(mapping)

	log.WithFields(logger.Fields{
		"at":          "i2cp.parseSessionOptions",
		"optionCount": len(optionsMap),
	}).Debug("parsing_session_options")

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

	log.WithFields(logger.Fields{
		"at":        "i2cp.mappingToGoMap",
		"pairCount": len(values),
	}).Debug("converting_mapping_to_map")

	for _, pair := range values {
		if len(pair) != 2 {
			log.WithFields(logger.Fields{
				"at":          "i2cp.mappingToGoMap",
				"pair_length": len(pair),
			}).Warn("invalid_mapping_pair")
			continue
		}

		key, keyErr := pair[0].Data()
		value, valErr := pair[1].Data()

		if keyErr != nil || valErr != nil {
			log.WithFields(logger.Fields{
				"at":          "i2cp.mappingToGoMap",
				"key_error":   keyErr,
				"value_error": valErr,
			}).Warn("failed_to_extract_mapping_pair")
			continue
		}

		result[key] = value
	}

	log.WithFields(logger.Fields{
		"at":             "i2cp.mappingToGoMap",
		"extractedCount": len(result),
	}).Debug("mapping_converted")

	return result
}

// applyTunnelLengthOptions applies tunnel length configuration options.
// Keys: inbound.length, outbound.length
func applyTunnelLengthOptions(config *SessionConfig, options map[string]string) {
	if val, exists := options["inbound.length"]; exists {
		if length, err := strconv.Atoi(val); err == nil && length >= 0 && length <= 7 {
			log.WithFields(logger.Fields{
				"at":     "i2cp.applyTunnelLengthOptions",
				"option": "inbound.length",
				"value":  length,
			}).Debug("applied_tunnel_length_option")
			config.InboundTunnelLength = length
			markExplicitlySet(config, "InboundTunnelLength")
		} else {
			log.WithFields(logger.Fields{
				"at":     "i2cp.applyTunnelLengthOptions",
				"option": "inbound.length",
				"value":  val,
				"error":  err,
			}).Warn("invalid_inbound_length_option_using_default")
		}
	}

	if val, exists := options["outbound.length"]; exists {
		if length, err := strconv.Atoi(val); err == nil && length >= 0 && length <= 7 {
			log.WithFields(logger.Fields{
				"at":     "i2cp.applyTunnelLengthOptions",
				"option": "outbound.length",
				"value":  length,
			}).Debug("applied_tunnel_length_option")
			config.OutboundTunnelLength = length
			markExplicitlySet(config, "OutboundTunnelLength")
		} else {
			log.WithFields(logger.Fields{
				"at":     "i2cp.applyTunnelLengthOptions",
				"option": "outbound.length",
				"value":  val,
				"error":  err,
			}).Warn("invalid_outbound_length_option_using_default")
		}
	}
}

// markExplicitlySet records that a field was explicitly set during parsing.
func markExplicitlySet(config *SessionConfig, field string) {
	if config.ExplicitlySetFields == nil {
		config.ExplicitlySetFields = make(map[string]bool)
	}
	config.ExplicitlySetFields[field] = true
}

// applyTunnelQuantityOptions applies tunnel quantity configuration options.
// Keys: inbound.quantity, outbound.quantity, inbound.backupQuantity, outbound.backupQuantity
func applyTunnelQuantityOptions(config *SessionConfig, options map[string]string) {
	applyQuantityOption(config, options, "inbound.quantity", &config.InboundTunnelCount)
	applyQuantityOption(config, options, "outbound.quantity", &config.OutboundTunnelCount)
	logUnsupportedBackupQuantities(config, options)
}

// applyQuantityOption parses and applies a single tunnel quantity option if present.
// The value must be a valid integer in the range [1, 16].
func applyQuantityOption(config *SessionConfig, options map[string]string, key string, target *int) {
	val, exists := options[key]
	if !exists {
		return
	}
	quantity, err := strconv.Atoi(val)
	if err == nil && quantity >= 1 && quantity <= 16 {
		log.WithFields(logger.Fields{
			"at":     "i2cp.applyTunnelQuantityOptions",
			"option": key,
			"value":  quantity,
		}).Debug("applied_tunnel_quantity_option")
		*target = quantity
	} else {
		log.WithFields(logger.Fields{
			"at":     "i2cp.applyTunnelQuantityOptions",
			"option": key,
			"value":  val,
			"error":  err,
		}).Warn("invalid_tunnel_quantity_option_using_default")
	}
}

// logUnsupportedBackupQuantities logs and records backup quantity options that are
// not yet implemented in the SessionConfig.
func logUnsupportedBackupQuantities(config *SessionConfig, options map[string]string) {
	for _, key := range []string{"inbound.backupQuantity", "outbound.backupQuantity"} {
		if val, exists := options[key]; exists {
			log.WithFields(logger.Fields{
				"at":     "i2cp.applyTunnelQuantityOptions",
				"option": key,
				"value":  val,
				"status": "unsupported",
			}).Warn("backup tunnel quantity option not implemented - value ignored")
			recordUnsupportedOption(config, key, val)
		}
	}
}

// applyTunnelLifetimeOptions applies tunnel lifetime configuration options.
// Keys: inbound.lengthVariance, outbound.lengthVariance (affects lifetime calculation)
//
// NOTE: These options are parsed and acknowledged but NOT implemented:
//   - inbound.lengthVariance / outbound.lengthVariance: Variance is ignored, fixed 10-minute lifetime used
func applyTunnelLifetimeOptions(config *SessionConfig, options map[string]string) {
	for key, val := range options {
		if key == "inbound.lengthVariance" || key == "outbound.lengthVariance" {
			log.WithFields(logger.Fields{
				"at":     "i2cp.applyTunnelLifetimeOptions",
				"option": key,
				"value":  val,
				"status": "unsupported",
			}).Warn("tunnel lifetime variance option not implemented - fixed 10-minute lifetime used")
			recordUnsupportedOption(config, key, val)
		}
	}
}

// applyMessageOptions applies message-related configuration options.
// Keys: i2cp.messageReliability, i2cp.gzip, i2cp.encryptLeaseSet
//
// NOTE: These options are parsed and acknowledged but NOT implemented:
//   - i2cp.messageReliability: All messages use best-effort delivery regardless of setting
//   - i2cp.gzip: Payload compression is not performed
//   - i2cp.encryptLeaseSet: LeaseSet encryption is not supported
func applyMessageOptions(config *SessionConfig, options map[string]string) {
	unsupportedKeys := []string{"i2cp.messageReliability", "i2cp.gzip", "i2cp.encryptLeaseSet"}
	for _, key := range unsupportedKeys {
		if val, exists := options[key]; exists {
			log.WithFields(logger.Fields{
				"at":     "i2cp.applyMessageOptions",
				"option": key,
				"value":  val,
				"status": "unsupported",
			}).Warn("message option not implemented - value ignored; all messages use best-effort, no compression")
			recordUnsupportedOption(config, key, val)
		}
	}
}

// recordUnsupportedOption records an I2CP option that the client set but is
// not implemented. This allows clients to inspect SessionConfig.UnsupportedOptions
// after session creation to detect features that were silently ignored.
func recordUnsupportedOption(config *SessionConfig, key, value string) {
	if config.UnsupportedOptions == nil {
		config.UnsupportedOptions = make(map[string]string)
	}
	config.UnsupportedOptions[key] = value
}

// applyMetadataOptions applies metadata configuration options.
// Keys: inbound.nickname, outbound.nickname (for debugging)
func applyMetadataOptions(config *SessionConfig, options map[string]string) {
	// Check for nickname option (common in Java I2P clients)
	if val, exists := options["inbound.nickname"]; exists {
		log.WithFields(logger.Fields{
			"at":       "i2cp.applyMetadataOptions",
			"nickname": val,
		}).Debug("applied_inbound_nickname")
		config.Nickname = val
	} else if val, exists := options["outbound.nickname"]; exists {
		log.WithFields(logger.Fields{
			"at":       "i2cp.applyMetadataOptions",
			"nickname": val,
		}).Debug("applied_outbound_nickname")
		config.Nickname = val
	}
}

// ValidateSessionConfig validates session configuration values are within acceptable ranges.
// Returns error if validation fails.
func ValidateSessionConfig(config *SessionConfig) error {
	log.WithFields(logger.Fields{
		"at": "i2cp.ValidateSessionConfig",
	}).Debug("validating_session_config")

	if config == nil {
		log.WithFields(logger.Fields{
			"at": "i2cp.ValidateSessionConfig",
		}).Error("session_config_is_nil")
		return fmt.Errorf("session config is nil")
	}

	if err := validateTunnelLengths(config); err != nil {
		log.WithFields(logger.Fields{
			"at":    "i2cp.ValidateSessionConfig",
			"error": err.Error(),
		}).Error("tunnel_length_validation_failed")
		return err
	}

	if err := validateTunnelCounts(config); err != nil {
		log.WithFields(logger.Fields{
			"at":    "i2cp.ValidateSessionConfig",
			"error": err.Error(),
		}).Error("tunnel_count_validation_failed")
		return err
	}

	if err := validateTunnelLifetime(config); err != nil {
		log.WithFields(logger.Fields{
			"at":    "i2cp.ValidateSessionConfig",
			"error": err.Error(),
		}).Error("tunnel_lifetime_validation_failed")
		return err
	}

	if err := validateMessageQueueSize(config); err != nil {
		log.WithFields(logger.Fields{
			"at":    "i2cp.ValidateSessionConfig",
			"error": err.Error(),
		}).Error("message_queue_size_validation_failed")
		return err
	}

	log.WithFields(logger.Fields{
		"at":                   "i2cp.ValidateSessionConfig",
		"inboundTunnelLength":  config.InboundTunnelLength,
		"outboundTunnelLength": config.OutboundTunnelLength,
		"inboundTunnelCount":   config.InboundTunnelCount,
		"outboundTunnelCount":  config.OutboundTunnelCount,
		"messageQueueSize":     config.MessageQueueSize,
	}).Debug("session_config_validated_successfully")

	return nil
}

// validateTunnelLengths validates inbound and outbound tunnel length are within I2P spec limits (0-7 hops).
// Returns error if either tunnel length is out of range.
func validateTunnelLengths(config *SessionConfig) error {
	if config.InboundTunnelLength < 0 || config.InboundTunnelLength > 7 {
		log.WithFields(logger.Fields{
			"at":     "i2cp.validateTunnelLengths",
			"length": config.InboundTunnelLength,
			"min":    0,
			"max":    7,
		}).Error("invalid_inbound_tunnel_length")
		return fmt.Errorf("invalid inbound tunnel length: %d (must be 0-7)", config.InboundTunnelLength)
	}
	if config.OutboundTunnelLength < 0 || config.OutboundTunnelLength > 7 {
		log.WithFields(logger.Fields{
			"at":     "i2cp.validateTunnelLengths",
			"length": config.OutboundTunnelLength,
			"min":    0,
			"max":    7,
		}).Error("invalid_outbound_tunnel_length")
		return fmt.Errorf("invalid outbound tunnel length: %d (must be 0-7)", config.OutboundTunnelLength)
	}
	return nil
}

// validateTunnelCounts validates inbound and outbound tunnel counts are within reasonable limits (1-16).
// Returns error if either tunnel count is out of range.
func validateTunnelCounts(config *SessionConfig) error {
	if config.InboundTunnelCount < 1 || config.InboundTunnelCount > 16 {
		log.WithFields(logger.Fields{
			"at":    "i2cp.validateTunnelCounts",
			"count": config.InboundTunnelCount,
			"min":   1,
			"max":   16,
		}).Error("invalid_inbound_tunnel_count")
		return fmt.Errorf("invalid inbound tunnel count: %d (must be 1-16)", config.InboundTunnelCount)
	}
	if config.OutboundTunnelCount < 1 || config.OutboundTunnelCount > 16 {
		log.WithFields(logger.Fields{
			"at":    "i2cp.validateTunnelCounts",
			"count": config.OutboundTunnelCount,
			"min":   1,
			"max":   16,
		}).Error("invalid_outbound_tunnel_count")
		return fmt.Errorf("invalid outbound tunnel count: %d (must be 1-16)", config.OutboundTunnelCount)
	}
	return nil
}

// validateTunnelLifetime validates tunnel lifetime is within reasonable bounds (1 minute to 1 hour).
// Returns error if lifetime is out of range.
func validateTunnelLifetime(config *SessionConfig) error {
	if config.TunnelLifetime < 1*time.Minute || config.TunnelLifetime > 60*time.Minute {
		log.WithFields(logger.Fields{
			"at":       "i2cp.validateTunnelLifetime",
			"lifetime": config.TunnelLifetime,
			"min":      1 * time.Minute,
			"max":      60 * time.Minute,
		}).Error("invalid_tunnel_lifetime")
		return fmt.Errorf("invalid tunnel lifetime: %v (must be 1m-60m)", config.TunnelLifetime)
	}
	return nil
}

// validateMessageQueueSize validates message queue size is positive.
// Returns error if queue size is less than 1.
func validateMessageQueueSize(config *SessionConfig) error {
	if config.MessageQueueSize < 1 {
		log.WithFields(logger.Fields{
			"at":        "i2cp.validateMessageQueueSize",
			"queueSize": config.MessageQueueSize,
			"min":       1,
		}).Error("invalid_message_queue_size")
		return fmt.Errorf("invalid message queue size: %d (must be >= 1)", config.MessageQueueSize)
	}
	return nil
}
