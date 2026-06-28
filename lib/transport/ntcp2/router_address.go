package ntcp2

import (
	"fmt"
	"net"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/router_address"
	i2pcurve25519 "github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/nat"
	ntcp2noise "github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// logConversionStart logs the start of transport to RouterAddress conversion.
func logConversionStart() {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "converting_transport_to_router_address",
		"phase":  "startup",
		"step":   1,
	}).Debug("converting NTCP2Transport to RouterAddress")
}

// logNilTransportError logs an error when transport is nil.
func logNilTransportError() {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "nil_transport",
		"phase":  "startup",
	}).Error("cannot convert nil transport to RouterAddress")
}

// logAddressExtractionError logs an error during address extraction.
func logAddressExtractionError(err error) {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "address_extraction_failed",
		"phase":  "startup",
		"step":   2,
		"error":  err.Error(),
	}).Error("failed to extract transport address")
}

// logStaticKeyError logs an error during static key validation.
func logStaticKeyError(err error) {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "static_key_validation_failed",
		"phase":  "startup",
		"step":   3,
		"error":  err.Error(),
	}).Error("failed to validate and extract static key")
}

// logOptionsBuildError logs an error during router address options building.
func logOptionsBuildError(err error) {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "options_build_failed",
		"phase":  "startup",
		"step":   4,
		"error":  err.Error(),
	}).Error("failed to build router address options")
}

// logRouterAddressCreationError logs an error when creating RouterAddress fails.
func logRouterAddressCreationError(err error) {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "router_address_creation_failed",
		"phase":  "startup",
		"step":   5,
		"error":  err.Error(),
	}).Error("failed to create RouterAddress")
}

// logConversionSuccess logs successful conversion of transport to RouterAddress.
func logConversionSuccess(host, port string) {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "conversion_successful",
		"phase":  "startup",
		"host":   host,
		"port":   port,
	}).Info("successfully converted NTCP2Transport to RouterAddress")
}

// ConvertToRouterAddress converts an NTCP2Transport's listening address to a RouterAddress
// suitable for publishing in RouterInfo. This enables other routers to connect to this transport.
//
// The function extracts:
// - Host IP address from the transport's listener
// - Port number from the transport's listener
// - Static public key from the NTCP2 configuration
// - Initialization vector (IV) for AES obfuscation
//
// Returns a RouterAddress with transport style "NTCP2" and all required options,
// or an error if address extraction or conversion fails.
func ConvertToRouterAddress(transport *NTCP2Transport) (*router_address.RouterAddress, error) {
	logConversionStart()

	if transport == nil {
		logNilTransportError()
		return nil, oops.Errorf("transport cannot be nil")
	}

	host, port, options, err := prepareRouterAddressComponents(transport)
	if err != nil {
		return nil, err
	}

	routerAddress, err := createNTCP2RouterAddress(options)
	if err != nil {
		return nil, err
	}

	logConversionSuccess(host, port)
	return routerAddress, nil
}

// prepareRouterAddressComponents extracts and prepares all components needed for router address creation.
func prepareRouterAddressComponents(transport *NTCP2Transport) (host, port string, options map[string]string, err error) {
	host, port, err = extractTransportAddress(transport)
	if err != nil {
		logAddressExtractionError(err)
		return "", "", nil, err
	}

	staticKey, err := validateAndExtractStaticKey(transport)
	if err != nil {
		logStaticKeyError(err)
		return "", "", nil, err
	}

	// HIGH-1.3 fix: Load config atomically
	cfg := transport.config.Load()
	options, err = buildRouterAddressOptions(host, port, staticKey, cfg.Config)
	if err != nil {
		logOptionsBuildError(err)
		return "", "", nil, err
	}

	return host, port, options, nil
}

// createNTCP2RouterAddress creates an NTCP2 RouterAddress with the appropriate cost.
func createNTCP2RouterAddress(options map[string]string) (*router_address.RouterAddress, error) {
	cost := calculateNTCP2AddressCost(options)
	routerAddress, err := router_address.NewRouterAddress(cost, time.Time{}, router_address.NTCP2_TRANSPORT_STYLE, options)
	if err != nil {
		logRouterAddressCreationError(err)
		return nil, oops.Wrapf(err, "failed to create RouterAddress")
	}
	return routerAddress, nil
}

// calculateNTCP2AddressCost determines the cost based on whether the address is published or caps-only.
// Returns 3 for published addresses, 14 for caps-only (unpublished).
func calculateNTCP2AddressCost(options map[string]string) uint8 {
	if _, hasHost := options["host"]; hasHost {
		return 3 // COST_NTCP2_PUBLISHED
	}
	return 14 // COST_NTCP2_NON_PUBLISHED
}

// detectExternalIP returns the best routable local IP address to advertise when
// the listener is bound to an unspecified address (:: or 0.0.0.0). It prefers
// globally-routable IPv4 addresses, then any non-loopback non-link-local address.
// Returns "" if no suitable address is found.
func detectExternalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.WithError(err).Warn("detectExternalIP: failed to enumerate interface addresses")
		return ""
	}
	return findBestExternalIP(addrs)
}

// findBestExternalIP searches interface addresses for the best external IP.
// Prefers public IPv4; falls back to any non-private IP if no public IPv4 is found.
func findBestExternalIP(addrs []net.Addr) string {
	var fallback string
	for _, addr := range addrs {
		ip := extractIPFromAddr(addr)
		if ip == nil || shouldSkipIP(ip) {
			continue
		}

		if isPublicIPv4(ip) {
			return ip.String()
		}

		if fallback == "" && !ip.IsPrivate() {
			fallback = ip.String()
		}
	}
	return fallback
}

// extractIPFromAddr extracts net.IP from various address types.
func extractIPFromAddr(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

// shouldSkipIP returns true if the IP should be skipped (loopback, link-local, etc.).
func shouldSkipIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// isPublicIPv4 returns true if the IP is a publicly routable IPv4 address.
func isPublicIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	return !isSpecialUseIPv4(ip4)
}

// isPublicIP returns true if the IP string represents a publicly routable address
// that remote peers can reach. Private/RFC1918 and reserved ranges return false.
func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return !isSpecialUseIPv4(ip4)
	}
	return true
}

// isSpecialUseIPv4 returns true for non-routable special-use IPv4 ranges that
// should never be published as direct-reachability endpoints.
func isSpecialUseIPv4(ip net.IP) bool {
	if ip == nil || ip.To4() == nil {
		return false
	}
	if ip[0] == 100 && ip[1]&0xC0 == 64 {
		return true // 100.64.0.0/10 carrier-grade NAT
	}
	if ip[0] == 192 && ip[1] == 0 && ip[2] == 0 {
		return true // 192.0.0.0/24 IETF protocol assignments
	}
	if ip[0] == 192 && ip[1] == 0 && ip[2] == 2 {
		return true // 192.0.2.0/24 TEST-NET-1
	}
	if ip[0] == 198 && ip[1] == 51 && ip[2] == 100 {
		return true // 198.51.100.0/24 TEST-NET-2
	}
	if ip[0] == 203 && ip[1] == 0 && ip[2] == 113 {
		return true // 203.0.113.0/24 TEST-NET-3
	}
	if ip[0] >= 224 {
		return true // multicast and reserved classes
	}
	return false
}

// extractTransportAddress extracts and validates the host and port from the transport's listening address.
// Returns the host IP string, port string, and any error encountered during extraction.
func extractTransportAddress(transport *NTCP2Transport) (string, string, error) {
	addr := transport.Addr()
	if addr == nil {
		log.WithFields(logger.Fields{"at": "extractTransportAddress"}).Error("Transport has no listening address")
		return "", "", oops.Errorf("transport has no listening address")
	}

	return extractAddressComponents(addr)
}

// extractAddressComponents extracts host and port from various address types.
// Supports *ntcp2.Addr, *net.TCPAddr, and *nat.NATAddr.
func extractAddressComponents(addr net.Addr) (string, string, error) {
	switch typedAddr := addr.(type) {
	case *ntcp2noise.Addr:
		return extractFromNTCP2Addr(typedAddr)
	case *net.TCPAddr:
		return extractFromTCPAddr(typedAddr)
	case *nat.NATAddr:
		return extractFromNATAddr(typedAddr)
	default:
		log.Errorf("Expected *net.TCPAddr, *ntcp2.Addr, or *nat.NATAddr, got %T", addr)
		return "", "", oops.Errorf("unsupported address type %T", addr)
	}
}

// extractFromNTCP2Addr extracts host and port from an NTCP2Addr wrapper.
func extractFromNTCP2Addr(typedAddr *ntcp2noise.Addr) (string, string, error) {
	underlying := typedAddr.UnderlyingAddr()
	host, port, err := extractHostPort(underlying)
	if err != nil {
		log.Errorf("NTCP2Addr underlying address extraction failed: %v", err)
		return "", "", oops.Wrapf(err, "NTCP2Addr underlying address extraction failed")
	}
	return host, port, nil
}

// extractFromTCPAddr extracts host and port from a TCPAddr, handling unspecified IPs.
func extractFromTCPAddr(typedAddr *net.TCPAddr) (string, string, error) {
	host := resolveHostIP(typedAddr.IP)
	port := fmt.Sprintf("%d", typedAddr.Port)
	return host, port, nil
}

// extractFromNATAddr extracts host and port from a NATAddr, using external address.
func extractFromNATAddr(typedAddr *nat.NATAddr) (string, string, error) {
	host, port, err := net.SplitHostPort(typedAddr.ExternalAddr())
	if err != nil {
		return "", "", oops.Wrapf(err, "failed to parse NATAddr external address %q", typedAddr.ExternalAddr())
	}
	host = resolveUnspecifiedIP(host)
	return host, port, nil
}

// resolveHostIP returns the IP string, or detects external IP if the IP is nil or unspecified.
func resolveHostIP(ip net.IP) string {
	if ip == nil || ip.IsUnspecified() {
		if ext := detectExternalIP(); ext != "" {
			return ext
		}
		if ip != nil {
			return ip.String()
		}
		return ""
	}
	return ip.String()
}

// resolveUnspecifiedIP checks if a host string represents an unspecified IP and replaces it with detected external IP.
func resolveUnspecifiedIP(host string) string {
	if parsedIP := net.ParseIP(host); parsedIP != nil && parsedIP.IsUnspecified() {
		if ext := detectExternalIP(); ext != "" {
			return ext
		}
	}
	return host
}

// extractHostPort extracts host and port from an address that may be *net.TCPAddr or *nat.NATAddr.
func extractHostPort(addr net.Addr) (string, string, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return extractTCPAddrHostPort(a)
	case *nat.NATAddr:
		return extractNATAddrHostPort(a)
	default:
		return "", "", oops.Errorf("unsupported underlying address type %T", addr)
	}
}

// extractTCPAddrHostPort extracts host and port from a TCPAddr, using external IP fallback if needed.
func extractTCPAddrHostPort(addr *net.TCPAddr) (string, string, error) {
	ip := addr.IP
	port := fmt.Sprintf("%d", addr.Port)

	if ip == nil || ip.IsUnspecified() {
		if ext := detectExternalIP(); ext != "" {
			return ext, port, nil
		}
	}

	return ip.String(), port, nil
}

// extractNATAddrHostPort extracts host and port from a NATAddr, using external IP fallback if needed.
func extractNATAddrHostPort(addr *nat.NATAddr) (string, string, error) {
	host, port, err := net.SplitHostPort(addr.ExternalAddr())
	if err != nil {
		return "", "", oops.Wrapf(err, "failed to parse NATAddr external address %q", addr.ExternalAddr())
	}

	if parsedIP := net.ParseIP(host); parsedIP != nil && parsedIP.IsUnspecified() {
		if ext := detectExternalIP(); ext != "" {
			host = ext
		}
	}

	return host, port, nil
}

// validateAndExtractStaticKey validates the NTCP2 configuration and extracts the base64-encoded
// static PUBLIC key for publication in RouterAddress.
//
// IMPORTANT: The Config.StaticKey contains the X25519 PRIVATE key (used internally
// by the Noise handshake). The NTCP2 spec requires publishing the corresponding PUBLIC
// key as the 's=' parameter. This function derives the public key via X25519 scalar
// base multiplication before encoding.
//
// Returns the base64-encoded static public key string and any validation error encountered.
func validateAndExtractStaticKey(transport *NTCP2Transport) (string, error) {
	// HIGH-1.3 fix: Load config atomically
	cfg := transport.config.Load()
	if cfg == nil || cfg.Config == nil {
		log.WithFields(logger.Fields{"at": "validateAndExtractStaticKey"}).Error("Transport NTCP2 configuration is not initialized")
		return "", oops.Errorf("transport NTCP2 configuration is not initialized")
	}

	ntcp2Config := cfg.Config

	if len(ntcp2Config.StaticKey) != 32 {
		log.WithField("length", len(ntcp2Config.StaticKey)).Error("Invalid static key length")
		return "", oops.Errorf("invalid static key length: expected 32 bytes, got %d", len(ntcp2Config.StaticKey))
	}

	// Derive the X25519 public key from the private key.
	// StaticKey is the private key; the published 's=' must be the public key.
	privKey, err := i2pcurve25519.NewCurve25519PrivateKey(ntcp2Config.StaticKey)
	if err != nil {
		log.WithError(err).Error("Failed to create Curve25519 private key")
		return "", oops.Wrapf(err, "failed to create private key")
	}
	pubKey, err := privKey.Public()
	if err != nil {
		log.WithError(err).Error("Failed to derive public key from static private key")
		return "", oops.Wrapf(err, "failed to derive public key")
	}
	publicKey := pubKey.Bytes()

	staticKeyB64 := i2pbase64.I2PEncoding.EncodeToString(publicKey)
	return staticKeyB64, nil
}

// buildRouterAddressOptions constructs the options map for the RouterAddress with all required
// NTCP2 parameters including host, port, static key, and IV.
//
// Per I2P specification (https://geti2p.net/spec/ntcp2#published-addresses):
// - Static key 's': 32 bytes binary (X25519 public key), 44 bytes I2P base64-encoded
// - IV 'i': 16 bytes binary (big-endian), 24 bytes I2P base64-encoded
//
// Returns the options map and an error if validation fails.
func buildRouterAddressOptions(host, port, staticKey string, ntcp2Config *ntcp2noise.Config) (map[string]string, error) {
	// Validate IV length (required per spec: 16 bytes binary -> 24 bytes Base64)
	if len(ntcp2Config.ObfuscationIV) != 16 {
		return nil, oops.Errorf("invalid IV length: expected 16 bytes, got %d", len(ntcp2Config.ObfuscationIV))
	}

	if isPublicIP(host) {
		// Published address: include host, port, and IV so remote peers can connect directly.
		// Per I2P spec, 'i' (IV) is only present for published NTCP2 addresses.
		ivB64 := i2pbase64.I2PEncoding.EncodeToString(ntcp2Config.ObfuscationIV)
		options := map[string]string{
			"host": host,
			"port": port,
			"s":    staticKey,
			"i":    ivB64,
			"v":    "2",
		}
		return options, nil
	}

	// Unpublished (caps-only) address: the host is private/RFC1918 or unknown.
	// i2pd marks addresses with reserved-range IPs as eTransportUnknown, which sets
	// m_SupportedTransports=0 and triggers SetUnreachable(true) → reason_code=15.
	// Publishing a caps-only NTCP2 address (static key + caps, no host/port/IV) causes
	// i2pd to set address->published=false and still add eNTCP2V4 to supportedTransports.
	log.WithField("host", host).Debug("Host is not publicly routable; publishing caps-only NTCP2 address")
	options := map[string]string{
		"s":    staticKey,
		"caps": "4", // eV4 = 1 in i2pd AddressCaps; signals IPv4 NTCP2 capability
		"v":    "2",
	}
	return options, nil
}
