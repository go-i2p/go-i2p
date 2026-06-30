package i2cp

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
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
		log.WithFields(logger.Fields{
			"at":          "i2cp.ParseCreateSessionPayload",
			"payloadSize": len(payload),
			"required":    2,
		}).Error("create_session_payload_too_short")
		return nil, nil, oops.Errorf("create session payload too short: %d bytes", len(payload))
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
		return nil, nil, oops.Errorf("failed to parse destination: %w", err)
	}

	// Parse options mapping from remaining bytes
	config, err := parseSessionOptions(remainingBytes)
	if err != nil {
		// i2psnark compatibility: Log options parsing failure
		log.WithFields(logger.Fields{
			"at":             "i2cp.ParseCreateSessionPayload",
			"error":          err.Error(),
			"remainingBytes": len(remainingBytes),
		}).Error("failed_to_parse_session_options")
		return nil, nil, oops.Errorf("failed to parse session options: %w", err)
	}

	return dest, config, nil
}

// ParseCreateSessionSignedPayload parses and verifies a signed CreateSession payload.
//
// Strict wire format:
//   - Destination (variable length)
//   - Options size (2 bytes, big endian)
//   - Options mapping bytes (exactly options size bytes)
//   - Date (8 bytes)
//   - Signature (size depends on destination signing type)
func ParseCreateSessionSignedPayload(payload []byte) (*destination.Destination, *SessionConfig, error) {
	dest, remaining, err := parseDestination(payload)
	if err != nil {
		return nil, nil, err
	}

	config, signedLen, sig, err := parseSignedSessionBody(remaining)
	if err != nil {
		return nil, nil, err
	}

	if err := verifySignedSessionData(dest, payload[:len(payload)-len(sig)], sig); err != nil {
		return nil, nil, err
	}

	if signedLen != len(remaining)-len(sig) {
		return nil, nil, oops.Errorf("create session signed payload malformed: parsed length mismatch")
	}

	return dest, config, nil
}

// ParseReconfigureSessionPayload parses a ReconfigureSession message payload.
// Returns the updated session configuration.
//
// Wire format:
//   - Options Mapping (2-byte size + key=value; pairs)
//
// Note: The caller must strip the 2-byte SessionID prefix from the raw wire
// payload before calling this function. The SessionID is included in the wire
// payload but is extracted into msg.SessionID by ReadMessage.
func ParseReconfigureSessionPayload(payload []byte) (*SessionConfig, error) {
	if len(payload) < 2 {
		return nil, oops.Errorf("reconfigure session payload too short: %d bytes", len(payload))
	}

	// Parse options mapping
	config, err := parseSessionOptions(payload)
	if err != nil {
		return nil, oops.Errorf("failed to parse session options: %w", err)
	}

	return config, nil
}

// ParseReconfigureSessionSignedPayload parses and verifies a signed ReconfigureSession payload.
//
// Strict wire format:
//   - SessionID (2 bytes)
//   - Destination (variable length)
//   - Options size (2 bytes)
//   - Options mapping bytes
//   - Date (8 bytes)
//   - Signature (size depends on destination signing type)
func ParseReconfigureSessionSignedPayload(payload []byte) (uint16, *destination.Destination, *SessionConfig, error) {
	if len(payload) < 2 {
		return 0, nil, nil, oops.Errorf("reconfigure session payload too short: %d bytes", len(payload))
	}

	sessionID := binary.BigEndian.Uint16(payload[:2])
	body := payload[2:]

	dest, remaining, err := parseDestination(body)
	if err != nil {
		return 0, nil, nil, err
	}

	config, signedLen, sig, err := parseSignedSessionBody(remaining)
	if err != nil {
		return 0, nil, nil, err
	}

	if err := verifySignedSessionData(dest, body[:len(body)-len(sig)], sig); err != nil {
		return 0, nil, nil, err
	}

	if signedLen != len(remaining)-len(sig) {
		return 0, nil, nil, oops.Errorf("reconfigure session signed payload malformed: parsed length mismatch")
	}

	return sessionID, dest, config, nil
}

func parseSignedSessionBody(remaining []byte) (*SessionConfig, int, []byte, error) {
	if len(remaining) < 2 {
		return nil, 0, nil, oops.Errorf("signed session payload missing options length")
	}

	optionsSize := int(binary.BigEndian.Uint16(remaining[0:2]))
	optionsEnd := 2 + optionsSize
	if len(remaining) < optionsEnd+8 {
		return nil, 0, nil, oops.Errorf("signed session payload too short for options+date")
	}

	optionsBytes := remaining[:optionsEnd]
	config, err := parseSessionOptions(optionsBytes)
	if err != nil {
		return nil, 0, nil, oops.Errorf("failed to parse signed session options: %w", err)
	}

	dateEnd := optionsEnd + 8
	signature := remaining[dateEnd:]
	if len(signature) == 0 {
		return nil, 0, nil, oops.Errorf("signed session payload missing signature")
	}

	return config, dateEnd, signature, nil
}

func verifySignedSessionData(dest *destination.Destination, signedData []byte, sig []byte) error {
	if dest == nil || dest.KeysAndCert == nil || dest.KeyCertificate == nil {
		return oops.Errorf("destination missing key certificate")
	}

	expectedSigSize := dest.KeyCertificate.SignatureSize()
	if expectedSigSize <= 0 {
		return oops.Errorf("unknown signing type for destination")
	}
	if len(sig) != expectedSigSize {
		return oops.Errorf("invalid signature size: got %d, expected %d", len(sig), expectedSigSize)
	}

	spk, err := dest.SigningPublicKey()
	if err != nil {
		return oops.Errorf("failed to get destination signing public key: %w", err)
	}
	verifier, err := spk.NewVerifier()
	if err != nil {
		return oops.Errorf("failed to create verifier: %w", err)
	}
	if err := verifier.Verify(signedData, sig); err != nil {
		return oops.Errorf("signature verification failed: %w", err)
	}

	return nil
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
		return nil, nil, oops.Errorf("failed to read destination: %w", err)
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
		return nil, oops.Errorf("failed to parse session options mapping: %v", errs)
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

	return result
}

// applyTunnelLengthOptions applies tunnel length configuration options.
// Keys: inbound.length, outbound.length
// Valid range: 0-7 (number of hops)
func applyTunnelLengthOptions(config *SessionConfig, options map[string]string) {
	applyIntOption(config, options, "inbound.length",
		func(val int) { config.InboundTunnelLength = val },
		0, 7, "InboundTunnelLength")
	applyIntOption(config, options, "outbound.length",
		func(val int) { config.OutboundTunnelLength = val },
		0, 7, "OutboundTunnelLength")
}

// markExplicitlySet records that a field was explicitly set during parsing.
func markExplicitlySet(config *SessionConfig, field string) {
	if config.ExplicitlySetFields == nil {
		config.ExplicitlySetFields = make(map[string]bool)
	}
	config.ExplicitlySetFields[field] = true
}

// applyIntOption is a generic helper for parsing and applying integer options.
// Parses the value from options[key], validates it's within [min, max], then calls setter(value).
// Logs debug on success, warn on failure. Consolidation for H-7.
func applyIntOption(config *SessionConfig, options map[string]string, key string, setter func(int), min, max int, fieldName string) {
	val, exists := options[key]
	if !exists {
		return
	}

	intVal, err := strconv.Atoi(val)
	if err == nil && intVal >= min && intVal <= max {
		setter(intVal)
		markExplicitlySet(config, fieldName)
	} else {
		log.WithFields(logger.Fields{
			"at":     "i2cp.applyIntOption",
			"option": key,
			"value":  val,
			"error":  err,
		}).Warnf("invalid_%s_option_using_default", fieldName)
	}
}

// applyTunnelQuantityOptions applies tunnel quantity configuration options.
// Keys: inbound.quantity, outbound.quantity, inbound.backupQuantity, outbound.backupQuantity
func applyTunnelQuantityOptions(config *SessionConfig, options map[string]string) {
	applyQuantityOption(config, options, "inbound.quantity", &config.InboundTunnelCount)
	applyQuantityOption(config, options, "outbound.quantity", &config.OutboundTunnelCount)
	applyBackupQuantities(config, options)
}

// applyQuantityOption parses and applies a single tunnel quantity option if present.
// The value must be a valid integer in the range [1, 16].
// Consolidation for H-7.
func applyQuantityOption(config *SessionConfig, options map[string]string, key string, target *int) {
	applyIntOption(config, options, key,
		func(val int) { *target = val },
		1, 16, key)
}

// applyBackupQuantities parses and applies backup quantity options.
// These values are consumed by the tunnel pool manager in server_tunnels.go.
// Valid range: 0-16. Consolidation for H-7.
func applyBackupQuantities(config *SessionConfig, options map[string]string) {
	applyIntOption(config, options, "inbound.backupQuantity",
		func(val int) { config.InboundBackupQuantity = val },
		0, 16, "InboundBackupQuantity")
	applyIntOption(config, options, "outbound.backupQuantity",
		func(val int) { config.OutboundBackupQuantity = val },
		0, 16, "OutboundBackupQuantity")
}

// applyTunnelLifetimeOptions applies tunnel length variance configuration options.
// Keys: inbound.lengthVariance, outbound.lengthVariance
// Valid range: -7 to +7 (0 = no variance, negative = decrease only, positive = +/- range)
// Consolidation for H-7.
func applyTunnelLifetimeOptions(config *SessionConfig, options map[string]string) {
	applyIntOption(config, options, "inbound.lengthVariance",
		func(val int) { config.InboundLengthVariance = val },
		-7, 7, "InboundLengthVariance")
	applyIntOption(config, options, "outbound.lengthVariance",
		func(val int) { config.OutboundLengthVariance = val },
		-7, 7, "OutboundLengthVariance")
}

// applyMessageOptions applies message-related configuration options.
// Keys: i2cp.messageReliability, i2cp.gzip, i2cp.encryptLeaseSet, i2cp.dontPublishLeaseSet
//
// Implemented options:
//   - i2cp.messageReliability: Stored for relay decision logic ("BestEffort", "Guaranteed", "None")
//   - i2cp.gzip: Controls whether the I2CP client library compresses/decompresses payloads (default: true)
//   - i2cp.encryptLeaseSet: Enables LeaseSet encryption via UseEncryptedLeaseSet
//   - i2cp.dontPublishLeaseSet: Prevents LeaseSet publication to NetDB
func applyMessageOptions(config *SessionConfig, options map[string]string) {
	applyMessageReliability(config, options)
	applyGzipOption(config, options)
	applyBoolOption(config, options, "i2cp.encryptLeaseSet", "UseEncryptedLeaseSet",
		func() { config.UseEncryptedLeaseSet = true }, "enabled_encrypted_leaseset")
	applyBoolOption(config, options, "i2cp.dontPublishLeaseSet", "DontPublishLeaseSet",
		func() { config.DontPublishLeaseSet = true }, "disabled_leaseset_publication")
}

// applyMessageReliability handles the i2cp.messageReliability option.
func applyMessageReliability(config *SessionConfig, options map[string]string) {
	val, exists := options["i2cp.messageReliability"]
	if !exists {
		return
	}
	switch val {
	case "BestEffort":
		config.MessageReliability = val
		markExplicitlySet(config, "MessageReliability")

	case "None":
		// "None" delivery mode is not fully implemented; semantically it should
		// mean "don't even attempt delivery confirmation," but in practice this
		// implementation treats it the same as BestEffort (single attempt, no ack).
		config.MessageReliability = "BestEffort"
		markExplicitlySet(config, "MessageReliability")
		if config.UnsupportedOptions == nil {
			config.UnsupportedOptions = make(map[string]string)
		}
		config.UnsupportedOptions["i2cp.messageReliability"] = "None"
		log.WithFields(logger.Fields{
			"at":        "i2cp.applyMessageOptions",
			"option":    "i2cp.messageReliability",
			"requested": "None",
			"effective": "BestEffort",
			"reason":    "only BestEffort is implemented",
		}).Warn("message_reliability_downgrade")
	case "Guaranteed":
		// Guaranteed delivery is not implemented; fall back to BestEffort
		// and record the unsupported option so clients can detect this.
		config.MessageReliability = "BestEffort"
		markExplicitlySet(config, "MessageReliability")
		if config.UnsupportedOptions == nil {
			config.UnsupportedOptions = make(map[string]string)
		}
		config.UnsupportedOptions["i2cp.messageReliability"] = "Guaranteed"
		log.WithFields(logger.Fields{
			"at":        "i2cp.applyMessageOptions",
			"option":    "i2cp.messageReliability",
			"requested": "Guaranteed",
			"effective": "BestEffort",
			"reason":    "only BestEffort is implemented",
		}).Warn("message_reliability_downgrade")
	default:
		log.WithFields(logger.Fields{
			"at":     "i2cp.applyMessageOptions",
			"option": "i2cp.messageReliability",
			"value":  val,
		}).Warn("unrecognized message reliability value - using default BestEffort")
	}
}

// applyBoolOption applies a boolean "true" option from the options map.
func applyBoolOption(config *SessionConfig, options map[string]string, key, fieldName string, setter func(), logMsg string) {
	if val, exists := options[key]; exists && val == "true" {
		setter()
		markExplicitlySet(config, fieldName)
	}
}

// applyGzipOption handles the i2cp.gzip option.
// Per I2CP spec, gzip compression is performed by the I2CP client library,
// not the router. The router stores this flag so that session configuration
// can be queried by the client library to determine compression behavior.
// Default is true (enabled) per the specification.
func applyGzipOption(config *SessionConfig, options map[string]string) {
	val, exists := options["i2cp.gzip"]
	if !exists {
		return
	}
	config.GzipEnabled = val == "true"
	markExplicitlySet(config, "GzipEnabled")
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
		log.WithFields(logger.Fields{
			"at": "i2cp.ValidateSessionConfig",
		}).Error("session_config_is_nil")
		return oops.Errorf("session config is nil")
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
		return oops.Errorf("invalid inbound tunnel length: %d (must be 0-7)", config.InboundTunnelLength)
	}
	if config.OutboundTunnelLength < 0 || config.OutboundTunnelLength > 7 {
		log.WithFields(logger.Fields{
			"at":     "i2cp.validateTunnelLengths",
			"length": config.OutboundTunnelLength,
			"min":    0,
			"max":    7,
		}).Error("invalid_outbound_tunnel_length")
		return oops.Errorf("invalid outbound tunnel length: %d (must be 0-7)", config.OutboundTunnelLength)
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
		return oops.Errorf("invalid inbound tunnel count: %d (must be 1-16)", config.InboundTunnelCount)
	}
	if config.OutboundTunnelCount < 1 || config.OutboundTunnelCount > 16 {
		log.WithFields(logger.Fields{
			"at":    "i2cp.validateTunnelCounts",
			"count": config.OutboundTunnelCount,
			"min":   1,
			"max":   16,
		}).Error("invalid_outbound_tunnel_count")
		return oops.Errorf("invalid outbound tunnel count: %d (must be 1-16)", config.OutboundTunnelCount)
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
		return oops.Errorf("invalid tunnel lifetime: %v (must be 1m-60m)", config.TunnelLifetime)
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
		return oops.Errorf("invalid message queue size: %d (must be >= 1)", config.MessageQueueSize)
	}
	return nil
}
