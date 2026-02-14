package bootstrap

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
)

// ValidationStats tracks statistics about RouterInfo validation during bootstrap
type ValidationStats struct {
	TotalProcessed     int
	ValidRouterInfos   int
	InvalidRouterInfos int
	InvalidReasons     map[string]int
}

// NewValidationStats creates a new ValidationStats instance
func NewValidationStats() *ValidationStats {
	return &ValidationStats{
		InvalidReasons: make(map[string]int),
	}
}

// RecordValid increments the valid RouterInfo count
func (vs *ValidationStats) RecordValid() {
	vs.TotalProcessed++
	vs.ValidRouterInfos++
}

// RecordInvalid increments the invalid RouterInfo count and tracks the reason
func (vs *ValidationStats) RecordInvalid(reason string) {
	vs.TotalProcessed++
	vs.InvalidRouterInfos++
	vs.InvalidReasons[reason]++
}

// ValidityRate returns the percentage of valid RouterInfos
func (vs *ValidationStats) ValidityRate() float64 {
	if vs.TotalProcessed == 0 {
		return 0.0
	}
	return float64(vs.ValidRouterInfos) / float64(vs.TotalProcessed) * 100.0
}

// LogSummary logs a summary of the validation statistics
func (vs *ValidationStats) LogSummary(phase string) {
	log.WithFields(logger.Fields{
		"at":              "ValidationStats.LogSummary",
		"phase":           phase,
		"total_processed": vs.TotalProcessed,
		"valid":           vs.ValidRouterInfos,
		"invalid":         vs.InvalidRouterInfos,
		"validity_rate":   fmt.Sprintf("%.1f%%", vs.ValidityRate()),
	}).Info("RouterInfo validation summary")

	if vs.InvalidRouterInfos > 0 {
		log.WithFields(logger.Fields{
			"at":              "ValidationStats.LogSummary",
			"phase":           phase,
			"invalid_reasons": vs.InvalidReasons,
		}).Debug("Invalid RouterInfo breakdown by reason")
	}
}

// classifyRouterInfo checks connectivity, structural validity, and signature
// for a single RouterInfo. It records the result in stats and returns true if
// the RouterInfo is valid, false otherwise. The caller and source parameters
// are used only for log context.
func classifyRouterInfo(ri router_info.RouterInfo, stats *ValidationStats, caller, source string) bool {
	if !HasDirectConnectivity(ri) {
		stats.RecordInvalid("no direct NTCP2 connectivity (introducer-only or missing host/port)")
		log.WithFields(logger.Fields{
			"at":          caller,
			"phase":       "pre-filter",
			"reason":      "no direct NTCP2 connectivity",
			"router_hash": GetRouterHashString(ri),
			"source":      source,
		}).Debug("skipping RouterInfo without direct NTCP2 connectivity")
		return false
	}

	if err := ValidateRouterInfo(ri); err != nil {
		stats.RecordInvalid(err.Error())
		log.WithFields(logger.Fields{
			"at":          caller,
			"phase":       "validation",
			"reason":      "invalid RouterInfo",
			"error":       err.Error(),
			"router_hash": GetRouterHashString(ri),
			"source":      source,
		}).Debug("skipping invalid RouterInfo")
		return false
	}

	if err := VerifyRouterInfoSignature(ri); err != nil {
		stats.RecordInvalid("signature verification failed")
		log.WithFields(logger.Fields{
			"at":          caller,
			"phase":       "validation",
			"reason":      "signature verification failed",
			"error":       err.Error(),
			"router_hash": GetRouterHashString(ri),
			"source":      source,
		}).Warn("rejecting RouterInfo with invalid signature")
		return false
	}

	stats.RecordValid()
	return true
}

// logInvalidRouterInfos emits a warning if any RouterInfos failed validation,
// including counts, validity rate, and reason breakdown.
func logInvalidRouterInfos(stats *ValidationStats, caller, source string) {
	if stats.InvalidRouterInfos > 0 {
		log.WithFields(logger.Fields{
			"at":              caller,
			"phase":           "validation",
			"source":          source,
			"invalid_count":   stats.InvalidRouterInfos,
			"valid_count":     stats.ValidRouterInfos,
			"validity_rate":   fmt.Sprintf("%.1f%%", stats.ValidityRate()),
			"invalid_reasons": stats.InvalidReasons,
		}).Warn("some RouterInfos failed validation")
	}
}

// extractNTCP2Transport extracts and validates the transport style from a RouterAddress.
// Returns true if the address uses NTCP2 transport, false otherwise.
func extractNTCP2Transport(addr *router_address.RouterAddress) bool {
	style := addr.TransportStyle()
	styleBytes, err := style.Data()
	if err != nil {
		return false
	}
	return strings.EqualFold(string(styleBytes), "ntcp2")
}

// extractSSU2Transport checks if a RouterAddress uses the SSU2 transport style.
func extractSSU2Transport(addr *router_address.RouterAddress) bool {
	style := addr.TransportStyle()
	styleBytes, err := style.Data()
	if err != nil {
		return false
	}
	return strings.EqualFold(string(styleBytes), "ssu2")
}

// validateDirectHost checks if a RouterAddress has a valid, directly accessible host.
// Returns true if host extraction succeeds and the host is not nil, false otherwise.
func validateDirectHost(addr *router_address.RouterAddress) bool {
	host, err := addr.Host()
	return err == nil && host != nil
}

// validateDirectPort checks if a RouterAddress has a valid, non-empty port.
// Returns true if port extraction succeeds and the port is not empty, false otherwise.
func validateDirectPort(addr *router_address.RouterAddress) bool {
	port, err := addr.Port()
	return err == nil && port != ""
}

// HasDirectNTCP2Connectivity checks if a RouterInfo has at least one NTCP2 address
// with direct connectivity (host and port keys present, not introducer-only).
// This pre-filtering function prevents ERROR logs from the common package when
// attempting to extract host keys from introducer-only addresses.
//
// CRITICAL FIX #1: Pre-filter bootstrap peers before validation to prevent
// "RouterAddress missing required host key" errors for introducer-only addresses.
func HasDirectNTCP2Connectivity(ri router_info.RouterInfo) bool {
	addresses := ri.RouterAddresses()
	if len(addresses) == 0 {
		return false
	}

	for _, addr := range addresses {
		if !extractNTCP2Transport(addr) {
			continue
		}

		if !validateDirectHost(addr) {
			continue
		}

		if !validateDirectPort(addr) {
			continue
		}

		return true
	}

	return false
}

// HasDirectConnectivity checks if a RouterInfo has at least one address (NTCP2 or SSU2)
// with direct connectivity (host and port present, not introducer-only).
// This is a broader check than HasDirectNTCP2Connectivity that also accepts
// SSU2-only routers, which are valid directly connectable peers.
func HasDirectConnectivity(ri router_info.RouterInfo) bool {
	addresses := ri.RouterAddresses()
	if len(addresses) == 0 {
		return false
	}

	for _, addr := range addresses {
		isNTCP2 := extractNTCP2Transport(addr)
		isSSU2 := extractSSU2Transport(addr)
		if !isNTCP2 && !isSSU2 {
			continue
		}

		if !validateDirectHost(addr) {
			continue
		}

		if !validateDirectPort(addr) {
			continue
		}

		return true
	}

	return false
}

// ValidateRouterInfo performs comprehensive validation on a RouterInfo
// Returns nil if valid, otherwise returns an error describing the validation failure
func ValidateRouterInfo(ri router_info.RouterInfo) error {
	// Check if RouterInfo has any addresses
	addresses := ri.RouterAddresses()
	if len(addresses) == 0 {
		return errors.New("no router addresses")
	}

	// Check if at least one valid address exists
	hasValidAddress := false
	var lastErr error

	for _, addr := range addresses {
		if err := ValidateRouterAddress(addr); err == nil {
			hasValidAddress = true
			break
		} else {
			lastErr = err
		}
	}

	if !hasValidAddress {
		if lastErr != nil {
			return fmt.Errorf("no valid router addresses found (last error: %v)", lastErr)
		}
		return errors.New("no valid router addresses found")
	}

	return nil
}

// ValidateRouterAddress validates a single RouterAddress
// Returns nil if valid, otherwise returns an error describing the validation failure
func ValidateRouterAddress(addr *router_address.RouterAddress) error {
	// Check transport style
	style := addr.TransportStyle()
	styleBytes, err := style.Data()
	if err != nil {
		return fmt.Errorf("invalid transport style: %w", err)
	}
	styleStr := string(styleBytes)

	if styleStr == "" {
		return errors.New("empty transport style")
	}

	// For NTCP2, validate required keys
	if strings.EqualFold(styleStr, "ntcp2") {
		return ValidateNTCP2Address(addr)
	}

	// For SSU, validate required keys (basic validation)
	if strings.EqualFold(styleStr, "ssu") {
		return validateSSUAddress(addr)
	}

	// For SSU2, validate required keys (basic validation)
	if strings.EqualFold(styleStr, "ssu2") {
		return validateSSU2Address(addr)
	}

	// Unknown transport style, but don't fail - might be future protocol
	log.WithFields(logger.Fields{
		"at":              "ValidateRouterAddress",
		"transport_style": styleStr,
	}).Debug("Unknown transport style, accepting as potentially valid")

	return nil
}

// ValidateNTCP2Address validates NTCP2-specific requirements
func ValidateNTCP2Address(addr *router_address.RouterAddress) error {
	hostData, err := validateHostData(addr)
	if err != nil {
		return err
	}

	port, err := validatePortData(addr, hostData)
	if err != nil {
		return err
	}

	if err := validateTCPResolution(hostData, port); err != nil {
		return err
	}

	checkOptionalStaticKey(addr)
	return nil
}

// validateHostData retrieves and validates the host from the RouterAddress.
// Returns the host string if valid, or an error for missing, nil, or empty hosts.
func validateHostData(addr *router_address.RouterAddress) (string, error) {
	host, err := addr.Host()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "validateHostData",
			"phase":     "validation",
			"transport": "ntcp2",
			"reason":    "host key missing - normal for introducer-based/firewalled routers",
			"error":     err.Error(),
			"note":      "requires introducer support (not yet implemented)",
			"impact":    "none - will be skipped during peer selection",
		}).Debug("NTCP2 address is introducer-only (no direct connectivity)")
		return "", fmt.Errorf("NTCP2 address cannot retrieve host (introducer-based): %w", err)
	}

	if host == nil {
		log.WithFields(logger.Fields{
			"at":        "validateHostData",
			"phase":     "validation",
			"transport": "ntcp2",
			"reason":    "host key value is nil",
			"impact":    "peer cannot be contacted via NTCP2",
		}).Warn("NTCP2 host is nil")
		return "", errors.New("NTCP2 host is nil")
	}

	hostData := host.String()
	if hostData == "" {
		log.WithFields(logger.Fields{
			"at":        "validateHostData",
			"phase":     "validation",
			"transport": "ntcp2",
			"reason":    "host key value is empty string",
			"impact":    "peer cannot be contacted via NTCP2",
		}).Warn("NTCP2 host is empty")
		return "", errors.New("NTCP2 host is empty")
	}

	return hostData, nil
}

// validatePortData retrieves and validates the port from the RouterAddress.
// Returns the port string if valid, or an error for missing or empty ports.
func validatePortData(addr *router_address.RouterAddress, hostData string) (string, error) {
	port, err := addr.Port()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "validatePortData",
			"phase":     "validation",
			"transport": "ntcp2",
			"reason":    "port key missing or malformed in RouterAddress mapping",
			"error":     err.Error(),
			"host":      hostData,
			"impact":    "peer cannot be contacted via NTCP2",
		}).Warn("RouterAddress missing required port key")
		return "", fmt.Errorf("NTCP2 address cannot retrieve port: %w", err)
	}

	if port == "" {
		log.WithFields(logger.Fields{
			"at":        "validatePortData",
			"phase":     "validation",
			"transport": "ntcp2",
			"reason":    "port key value is empty string",
			"host":      hostData,
			"impact":    "peer cannot be contacted via NTCP2",
		}).Warn("NTCP2 port is empty")
		return "", errors.New("NTCP2 port is empty")
	}

	return port, nil
}

// validateTCPResolution validates that the host:port combination forms a syntactically
// valid TCP address. Unlike the previous implementation, this does NOT perform live
// DNS resolution, which was slow and caused valid RouterInfos to be rejected during
// reseed processing due to transient DNS failures.
func validateTCPResolution(hostData, port string) error {
	// Validate host is non-empty
	if hostData == "" {
		return fmt.Errorf("NTCP2 address has empty host")
	}

	// Validate port is a valid number in range (already parsed by caller, but
	// verify the combined address is well-formed)
	hostPort := net.JoinHostPort(hostData, port)

	// Use net.SplitHostPort to verify the address is syntactically valid
	// without performing DNS resolution
	_, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "validateTCPResolution",
			"phase":     "validation",
			"transport": "ntcp2",
			"reason":    "malformed host:port",
			"host_port": hostPort,
			"error":     err.Error(),
			"impact":    "peer address is syntactically invalid",
		}).Warn("Invalid NTCP2 address discovered")
		return fmt.Errorf("NTCP2 address is malformed %s: %w", hostPort, err)
	}
	return nil
}

// checkOptionalStaticKey checks for the optional static key in NTCP2 addresses.
// Logs a debug message if the static key is missing.
func checkOptionalStaticKey(addr *router_address.RouterAddress) {
	if !addr.CheckOption("s") {
		log.WithFields(logger.Fields{
			"at":    "checkOptionalStaticKey",
			"issue": "missing static key",
		}).Debug("NTCP2 address missing optional 's' (static key)")
	}
}

// validateSSUAddress validates SSU-specific requirements
func validateSSUAddress(addr *router_address.RouterAddress) error {
	// Use the same API as runtime transport - addr.Host() is the single source of truth
	host, err := addr.Host()
	if err != nil {
		return fmt.Errorf("SSU address cannot retrieve host: %w", err)
	}

	if host == nil {
		return errors.New("SSU host is nil")
	}

	hostData := host.String()
	if hostData == "" {
		return errors.New("SSU host is empty")
	}

	// Use the same API as runtime transport - addr.Port() is the single source of truth
	port, err := addr.Port()
	if err != nil {
		return fmt.Errorf("SSU address cannot retrieve port: %w", err)
	}

	if port == "" {
		return errors.New("SSU port is empty")
	}

	return nil
}

// validateSSU2Address validates SSU2-specific requirements
func validateSSU2Address(addr *router_address.RouterAddress) error {
	// Use the same API as runtime transport - addr.Host() is the single source of truth
	host, err := addr.Host()
	if err != nil {
		return fmt.Errorf("SSU2 address cannot retrieve host: %w", err)
	}

	if host == nil {
		return errors.New("SSU2 host is nil")
	}

	hostData := host.String()
	if hostData == "" {
		return errors.New("SSU2 host is empty")
	}

	// Use the same API as runtime transport - addr.Port() is the single source of truth
	port, err := addr.Port()
	if err != nil {
		return fmt.Errorf("SSU2 address cannot retrieve port: %w", err)
	}

	if port == "" {
		return errors.New("SSU2 port is empty")
	}

	return nil
}

// GetRouterHashString returns a hex string representation of the RouterInfo's IdentHash
// This is a helper function to avoid duplication in logging
func GetRouterHashString(ri router_info.RouterInfo) string {
	hash, err := ri.IdentHash()
	if err != nil {
		return "<error>"
	}
	hashBytes := hash[:]
	if len(hashBytes) < 8 {
		return fmt.Sprintf("%x", hashBytes)
	}
	return fmt.Sprintf("%x", hashBytes[:8]) // First 8 bytes for brevity
}

// VerifyRouterInfoSignature cryptographically verifies that a RouterInfo's signature
// is valid by checking it against the signing public key embedded in the RouterIdentity.
//
// The verification process:
//  1. Serialize the RouterInfo to bytes (which includes the signature at the end)
//  2. Determine the signature size from the RouterIdentity's key certificate
//  3. Split the serialized bytes into data (without signature) and signature
//  4. Create a verifier from the signing public key
//  5. Verify the signature against the data
//
// This prevents accepting RouterInfos with forged identity hashes from compromised
// reseed servers, which is critical for bootstrap trust.
func VerifyRouterInfoSignature(ri router_info.RouterInfo) error {
	fullBytes, err := ri.Bytes()
	if err != nil {
		return fmt.Errorf("failed to serialize RouterInfo: %w", err)
	}

	identity := ri.RouterIdentity()
	if identity == nil {
		return errors.New("RouterInfo has nil RouterIdentity")
	}

	if err := validateSignaturePresent(ri); err != nil {
		return err
	}

	expectedSigSize, err := resolveExpectedSigSize(identity)
	if err != nil {
		return err
	}

	return verifySignatureBytes(fullBytes, expectedSigSize, identity)
}

// validateSignaturePresent checks that the RouterInfo has a non-empty signature.
func validateSignaturePresent(ri router_info.RouterInfo) error {
	sig := ri.Signature()
	sigBytes := sig.Bytes()
	if len(sigBytes) == 0 {
		return errors.New("RouterInfo has empty signature")
	}
	return nil
}

// resolveExpectedSigSize determines the expected signature size based on the key certificate's
// signing key type.
func resolveExpectedSigSize(identity *router_identity.RouterIdentity) (int, error) {
	sigType := identity.KeyCertificate.SigningPublicKeyType()
	expectedSigSize, err := key_certificate.GetSignatureSize(sigType)
	if err != nil {
		return 0, fmt.Errorf("unknown signature type %d: %w", sigType, err)
	}
	return expectedSigSize, nil
}

// verifySignatureBytes splits the serialized RouterInfo into data and signature portions,
// then verifies the signature cryptographically.
func verifySignatureBytes(fullBytes []byte, expectedSigSize int, identity *router_identity.RouterIdentity) error {
	if len(fullBytes) <= expectedSigSize {
		return fmt.Errorf("RouterInfo too short (%d bytes) for signature size %d",
			len(fullBytes), expectedSigSize)
	}

	signingPubKey, err := identity.SigningPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get signing public key: %w", err)
	}

	dataBytes := fullBytes[:len(fullBytes)-expectedSigSize]
	sigFromBytes := fullBytes[len(fullBytes)-expectedSigSize:]

	verifier, err := signingPubKey.NewVerifier()
	if err != nil {
		return fmt.Errorf("failed to create signature verifier: %w", err)
	}

	if err := verifier.Verify(dataBytes, sigFromBytes); err != nil {
		return fmt.Errorf("RouterInfo signature verification failed: %w", err)
	}

	return nil
}
