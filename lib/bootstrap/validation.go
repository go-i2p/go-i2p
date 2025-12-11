package bootstrap

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/go-i2p/common/router_address"
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
		// Check transport style
		style := addr.TransportStyle()
		styleBytes, err := style.Data()
		if err != nil {
			continue
		}

		// Only consider NTCP2 addresses
		if !strings.EqualFold(string(styleBytes), "ntcp2") {
			continue
		}

		// Check if this address has direct connectivity by trying to extract host and port
		// We check using the standard methods but suppress errors
		// If either extraction fails, this is an introducer-only address
		host, hostErr := addr.Host()
		if hostErr != nil || host == nil {
			continue
		}

		port, portErr := addr.Port()
		if portErr != nil || port == "" {
			continue
		}

		// Both host and port keys exist and are valid - this is a directly dialable NTCP2 address
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
	// Actually try to retrieve the host - this is what NTCP2 transport does
	// CheckOption() may return true even when the key doesn't exist in the mapping
	// Note: Missing host key is NORMAL for introducer-based NTCP2 addresses
	host, err := addr.Host()
	if err != nil {
		// This is expected for introducer-only addresses - log at debug level to reduce noise
		// Introducer-based addresses are used for routers behind NAT/firewalls
		// This is NOT an error - it's standard I2P protocol behavior
		log.WithFields(logger.Fields{
			"at":        "ValidateNTCP2Address",
			"phase":     "validation",
			"transport": "ntcp2",
			"reason":    "host key missing - normal for introducer-based/firewalled routers",
			"error":     err.Error(),
			"note":      "requires introducer support (not yet implemented)",
		}).Debug("NTCP2 address is introducer-only (no direct connectivity)")
		return fmt.Errorf("NTCP2 address cannot retrieve host (introducer-based): %w", err)
	}

	if host == nil {
		log.WithFields(logger.Fields{
			"at":        "ValidateNTCP2Address",
			"phase":     "validation",
			"transport": "ntcp2",
			"reason":    "host key value is nil",
			"impact":    "peer cannot be contacted via NTCP2",
		}).Warn("NTCP2 host is nil")
		return errors.New("NTCP2 host is nil")
	}

	hostData := host.String()
	if hostData == "" {
		log.WithFields(logger.Fields{
			"at":        "ValidateNTCP2Address",
			"phase":     "validation",
			"transport": "ntcp2",
			"reason":    "host key value is empty string",
			"impact":    "peer cannot be contacted via NTCP2",
		}).Warn("NTCP2 host is empty")
		return errors.New("NTCP2 host is empty")
	}

	// Actually try to retrieve the port - this is what NTCP2 transport does
	port, err := addr.Port()
	if err != nil {
		// Enhanced logging for Issue #1: RouterAddress missing required port key
		log.WithFields(logger.Fields{
			"at":        "ValidateNTCP2Address",
			"phase":     "validation",
			"transport": "ntcp2",
			"reason":    "port key missing or malformed in RouterAddress mapping",
			"error":     err.Error(),
			"host":      hostData,
			"impact":    "peer cannot be contacted via NTCP2",
		}).Warn("RouterAddress missing required port key")
		return fmt.Errorf("NTCP2 address cannot retrieve port: %w", err)
	}

	if port == "" {
		log.WithFields(logger.Fields{
			"at":        "ValidateNTCP2Address",
			"phase":     "validation",
			"transport": "ntcp2",
			"reason":    "port key value is empty string",
			"host":      hostData,
			"impact":    "peer cannot be contacted via NTCP2",
		}).Warn("NTCP2 port is empty")
		return errors.New("NTCP2 port is empty")
	}

	// Try to actually resolve the address to catch invalid IPs early
	// Use net.JoinHostPort to properly handle IPv6 addresses (wraps them in brackets)
	hostPort := net.JoinHostPort(hostData, port)
	_, err = net.ResolveTCPAddr("tcp", hostPort)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "ValidateNTCP2Address",
			"phase":     "validation",
			"transport": "ntcp2",
			"reason":    "cannot resolve host:port as valid TCP address",
			"host_port": hostPort,
			"error":     err.Error(),
			"impact":    "peer address is malformed or unresolvable",
		}).Warn("Invalid NTCP2 address discovered")
		return fmt.Errorf("NTCP2 address cannot resolve %s: %w", hostPort, err)
	}

	// Optional: validate static key exists (common in NTCP2)
	if !addr.CheckOption("s") {
		log.WithFields(logger.Fields{
			"at":    "validateNTCP2Address",
			"issue": "missing static key",
		}).Debug("NTCP2 address missing optional 's' (static key)")
	}

	return nil
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
