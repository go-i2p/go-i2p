package ssu2

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/nat"
	"github.com/go-i2p/go-i2p/lib/transport"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/samber/oops"
	"golang.org/x/crypto/curve25519"
)

// SupportsSSU2 checks if a RouterInfo has an SSU2 transport address.
func SupportsSSU2(routerInfo *router_info.RouterInfo) bool {
	if routerInfo == nil {
		return false
	}
	for _, addr := range routerInfo.RouterAddresses() {
		if isSSU2Transport(addr) {
			return true
		}
	}
	return false
}

// isSSU2Transport checks if a router address uses the SSU2 transport style.
func isSSU2Transport(addr *router_address.RouterAddress) bool {
	style := addr.TransportStyle()
	str, err := style.Data()
	if err != nil {
		return false
	}
	return strings.EqualFold(str, router_address.SSU2_TRANSPORT_STYLE)
}

// HasDirectConnectivity checks if a RouterAddress has direct SSU2 connectivity.
// Returns true if the address has both host and port (directly dialable).
// Returns false for introducer-only addresses.
func HasDirectConnectivity(addr *router_address.RouterAddress) bool {
	if addr == nil {
		return false
	}
	if !isSSU2Transport(addr) {
		return false
	}
	if !addr.HasValidHost() {
		return false
	}
	if !addr.HasValidPort() {
		return false
	}
	return true
}

// HasDialableSSU2Address checks if a RouterInfo has at least one directly dialable
// SSU2 address with a valid host and port.
func HasDialableSSU2Address(routerInfo *router_info.RouterInfo) bool {
	if routerInfo == nil {
		return false
	}
	for _, addr := range routerInfo.RouterAddresses() {
		if HasDirectConnectivity(addr) {
			return true
		}
	}
	return false
}

// Redirect to shared transport.ProbeIPv6 (consolidation H-5; mirrors ntcp2.probeIPv6)
// probeIPv6 wraps the shared transport.ProbeIPv6 for backward compatibility within ssu2 package.
func probeIPv6() bool {
	return transport.ProbeIPv6()
}

// ExtractSSU2Addr extracts the SSU2 network address from a RouterInfo structure.
// It returns a *net.UDPAddr for the best SSU2 transport address found, using a
// two-pass strategy: IPv4 addresses are preferred; IPv6 is only returned when
// the host has confirmed global-unicast IPv6 connectivity (AUDIT FIX-2 / RC-C).
func ExtractSSU2Addr(routerInfo router_info.RouterInfo) (*net.UDPAddr, error) {
	ipv6Fallback := searchForSSU2Address(routerInfo.RouterAddresses())
	if ipv6Fallback != nil {
		return ipv6Fallback, nil
	}
	return nil, ErrInvalidRouterInfo
}

// searchForSSU2Address searches router addresses for an SSU2 UDP address.
// Prefers IPv4; returns IPv6 fallback if IPv6 connectivity is available.
func searchForSSU2Address(addresses []*router_address.RouterAddress) *net.UDPAddr {
	var ipv6Fallback *net.UDPAddr
	for _, addr := range addresses {
		if !isSSU2Transport(addr) {
			continue
		}

		udpAddr, err := resolveUDPAddress(addr)
		if err != nil {
			log.WithField("error", err.Error()).Debug("Failed to resolve SSU2 address, trying next")
			continue
		}

		if udpAddr.IP.To4() != nil {
			// IPv4 address — return immediately (preferred path).
			return udpAddr
		}

		// IPv6 — only keep if the local host has IPv6 connectivity.
		if ipv6Fallback == nil && probeIPv6() {
			ipv6Fallback = udpAddr
		}
	}
	return ipv6Fallback
}

// ExtractSSU2IntroKey extracts the 32-byte introduction key from the "i" option
// of the first SSU2 RouterAddress found in ri.  The option value is
// I2P-base64-encoded (same alphabet as static keys).
// Returns an error if no SSU2 address carries a valid 32-byte intro key.
func ExtractSSU2IntroKey(ri router_info.RouterInfo) ([]byte, error) {
	introKey := findSSU2IntroKey(ri.RouterAddresses())
	if introKey != nil {
		return introKey, nil
	}
	return nil, oops.Errorf("no SSU2 address with a 32-byte intro key found in RouterInfo")
}

// findSSU2IntroKey searches router addresses for a valid 32-byte SSU2 introduction key.
func findSSU2IntroKey(addresses []*router_address.RouterAddress) []byte {
	for _, addr := range addresses {
		if !isSSU2Transport(addr) {
			continue
		}

		introKey := extractAndDecodeIntroKey(addr)
		if introKey != nil {
			return introKey
		}
	}
	return nil
}

// extractAndDecodeIntroKey extracts and decodes the introduction key from a router address.
func extractAndDecodeIntroKey(addr *router_address.RouterAddress) []byte {
	ivStr := addr.InitializationVectorString()
	if ivStr == nil {
		return nil
	}

	encoded, err := ivStr.Data()
	if err != nil {
		return nil
	}

	raw, err := i2pbase64.DecodeString(encoded)
	if err != nil {
		return nil
	}

	if len(raw) != 32 {
		return nil
	}

	return raw
}

// resolveUDPAddress extracts host and port from a RouterAddress and resolves to a UDP address.
func resolveUDPAddress(addr *router_address.RouterAddress) (*net.UDPAddr, error) {
	host, err := addr.Host()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to extract host")
	}

	port, err := addr.Port()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to extract port")
	}

	hostStr := host.String()
	// addr.Host() returns a net.Addr; extract the IP portion
	if h, _, splitErr := net.SplitHostPort(hostStr); splitErr == nil {
		hostStr = h
	}

	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(hostStr, port))
	if err != nil {
		return nil, oops.Wrapf(err, "failed to resolve UDP address")
	}
	return udpAddr, nil
}

// resolvePublishedHost returns the best host to publish in the RouterAddress.
// If the listener host is not itself publicly routable (RFC1918 private, CGNAT,
// a special-use range, or an unspecified/wildcard address) and a PeerTest- /
// NAT-PMP-confirmed external address is cached in the transport's natStateCache,
// the external address is returned; otherwise the raw listener host is returned
// unchanged. The substituted host is re-validated by buildSSU2Options, so a
// cached external that is itself non-public still falls back to a caps-only
// address rather than leaking a private host.
//
// BUG FIX: the previous gate only substituted for ip.IsPrivate() (RFC1918),
// which silently skipped CGNAT (100.64.0.0/10), special-use ranges, and
// wildcard binds — so a router behind carrier-grade NAT with a confirmed public
// external would publish an unreachable caps-only address despite being
// reachable. Gating on the canonical "not publicly routable" classifier closes
// that gap.
func resolvePublishedHost(host string, transport *SSU2Transport) string {
	if !isPublicHost(host) {
		if transport.natStateCache != nil {
			if cachedExt := transport.natStateCache.getExternal(); cachedExt != "" {
				return cachedExt
			}
		}
	}
	return host
}

// ConvertToRouterAddress converts an SSU2Transport's listening address to a RouterAddress
// suitable for publishing in RouterInfo.
func ConvertToRouterAddress(transport *SSU2Transport) (*router_address.RouterAddress, error) {
	host, portStr, err := validateAndExtractAddress(transport)
	if err != nil {
		return nil, err
	}

	host = resolvePublishedHost(host, transport)
	introducers := transport.GetIntroducers()
	options := buildSSU2Options(host, portStr, transport, introducers)
	cost := calculateSSU2AddressCost(options)

	return createSSU2RouterAddress(cost, options)
}

// validateAndExtractAddress validates the transport and extracts host/port from its address.
func validateAndExtractAddress(transport *SSU2Transport) (host, portStr string, err error) {
	if transport == nil {
		return "", "", oops.Errorf("transport cannot be nil")
	}

	addr := transport.Addr()
	if addr == nil {
		return "", "", oops.Errorf("transport has no listener address")
	}

	return extractHostPort(addr)
}

// calculateSSU2AddressCost determines the RouterAddress cost based on reachability.
// Returns 8 for published/introducer-reachable addresses, 15 for caps-only unpublished.
func calculateSSU2AddressCost(options map[string]string) uint8 {
	if _, hasHost := options["host"]; hasHost {
		return 8
	}
	if caps, hasCaps := options["caps"]; hasCaps && strings.Contains(caps, "B") {
		// Introducer-reachable: peers can reach us via the listed
		// introducers, so this is "directly reachable" in cost terms.
		return 8
	}
	return 15
}

// createSSU2RouterAddress creates a RouterAddress with the given cost and options.
func createSSU2RouterAddress(cost uint8, options map[string]string) (*router_address.RouterAddress, error) {
	ra, err := router_address.NewRouterAddress(cost, time.Time{}, "SSU2", options)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create RouterAddress")
	}
	return ra, nil
}

// buildSSU2Options assembles the option map for the published RouterAddress.
// When the host is not publicly routable AND we have at least one active
// introducer, the address is published in introducer-only form (no host/port,
// caps=B per the SSU2 spec) so that remote peers attempt to reach us via the
// listed introducers (Track C, hidden / firewalled router as "Charlie").
// When the host is not publicly routable AND no usable introducer is
// available, a caps-only SSU2 address is published (static key + intro key
// + caps, no host/port). Mirrors the NTCP2 caps-only fallback in
// ntcp2/router_address.go::buildRouterAddressOptions: publishing a private
// RFC1918 host in our RouterInfo causes Java I2P / i2pd to reject the entire
// RouterInfo as malformed, which silently kills NTCP2 SessionConfirmed (peer
// closes TCP without sending a Termination block) and prevents tunnel-build
// replies from ever returning to us.
// Otherwise the standard direct-connection options (host + port + keys +
// optional introducer hints) are emitted.
func buildSSU2Options(host, portStr string, transport *SSU2Transport, introducers []*ssu2noise.RegisteredIntroducer) map[string]string {
	if !isPublicHost(host) && hasUsableIntroducer(introducers) {
		familyCaps := ssu2AddressFamilyCaps(host)
		options := map[string]string{
			router_address.PROTOCOL_VERSION_OPTION_KEY: "2",
			router_address.CAPS_OPTION_KEY:             familyCaps + "B",
		}
		addStaticKeyOption(options, transport)
		addIntroKeyOption(options, transport)
		addIntroducerOptions(options, introducers)
		return options
	}
	if !isPublicHost(host) {
		// Hidden / firewalled with no introducer: publish caps-only so the
		// RouterInfo is still spec-conformant (no private hosts leaked) while
		// still advertising SSU2 capability. Peers cannot dial us directly,
		// which is correct: outbound sessions we initiated remain usable for
		// reply traffic (build replies, etc.).
		options := map[string]string{
			router_address.PROTOCOL_VERSION_OPTION_KEY: "2",
			router_address.CAPS_OPTION_KEY:             ssu2AddressFamilyCaps(host),
		}
		addStaticKeyOption(options, transport)
		addIntroKeyOption(options, transport)
		return options
	}
	options := buildBaseSSU2Options(host, portStr)
	addStaticKeyOption(options, transport)
	addIntroKeyOption(options, transport)
	addIntroducerOptions(options, introducers)
	return options
}

// isPublicHost returns true if host is a globally-routable, non-private IP.
// Mirrors ntcp2.isPublicIP so introducer-only publication uses the same
// reachability criterion as NTCP2's caps-only fallback. Delegates to the
// canonical classifier in lib/nat.
func isPublicHost(host string) bool {
	return nat.IsPubliclyRoutableHost(host)
}

// hasUsableIntroducer returns true if at least one entry in introducers carries
// both a router hash and a non-zero relay tag (the minimum needed for a remote
// peer to drive the introducer flow).
func hasUsableIntroducer(introducers []*ssu2noise.RegisteredIntroducer) bool {
	now := time.Now()
	for _, intro := range introducers {
		if intro == nil {
			continue
		}
		if len(intro.RouterHash) == 0 || intro.RelayTag == 0 || intro.AddedAt.IsZero() {
			continue
		}
		if intro.AddedAt.Add(4 * time.Hour).After(now) {
			return true
		}
	}
	return false
}

// ssu2AddressFamilyCaps derives address-family capability flags from host.
// Returns "4", "6", or "46" when the family cannot be determined.
func ssu2AddressFamilyCaps(host string) string {
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return "46"
	}
	if ip.To4() != nil {
		return "4"
	}
	return "6"
}

// extractHostPort unwraps SSU2Addr and extracts host and port from the listener address.
// Handles NATAddr (via lib/nat) to use the external address when available.
func extractHostPort(addr net.Addr) (string, string, error) {
	effectiveAddr := unwrapSSU2Addr(addr)

	if natAddr, ok := effectiveAddr.(*nat.NATAddr); ok {
		return extractNATAddrHostPort(natAddr)
	}

	return extractStandardHostPort(effectiveAddr)
}

// unwrapSSU2Addr unwraps an SSU2Addr to get the underlying address.
func unwrapSSU2Addr(addr net.Addr) net.Addr {
	if ssu2Addr, ok := addr.(*ssu2noise.SSU2Addr); ok {
		return ssu2Addr.UnderlyingAddr()
	}
	return addr
}

// extractNATAddrHostPort extracts host and port from a NATAddr's external address.
func extractNATAddrHostPort(natAddr *nat.NATAddr) (string, string, error) {
	host, portStr, err := splitNATHostPort(natAddr.ExternalAddr())
	if err != nil {
		return "", "", err
	}
	host = replaceUnspecifiedWithExternal(host)
	return host, portStr, nil
}

// splitNATHostPort splits an address string that may be an unbracketed IPv6+port
// produced by go-nat-listener (fmt.Sprintf("%s:%d", externalIP, port)).
// For IPv4 and already-bracketed IPv6 the standard net.SplitHostPort is used.
// For bare IPv6 (e.g. "2001:db8::1:4567") the last colon is treated as the
// host/port delimiter and brackets are added before retrying.
func splitNATHostPort(addr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(addr)
	if err == nil {
		return
	}
	// Detect unbracketed IPv6: more than one colon means IPv6, not IPv4.
	if strings.Count(addr, ":") < 2 {
		return "", "", oops.Wrapf(err, "failed to parse NATAddr external address %q", addr)
	}
	lastColon := strings.LastIndex(addr, ":")
	candidate := "[" + addr[:lastColon] + "]:" + addr[lastColon+1:]
	host, port, err2 := net.SplitHostPort(candidate)
	if err2 != nil {
		return "", "", oops.Wrapf(err, "failed to parse NATAddr external address %q", addr)
	}
	return host, port, nil
}

// extractStandardHostPort extracts host and port from a standard address using String().
func extractStandardHostPort(addr net.Addr) (string, string, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", "", oops.Wrapf(err, "failed to parse listener address")
	}
	host = replaceUnspecifiedWithExternal(host)
	return host, portStr, nil
}

// replaceUnspecifiedWithExternal replaces unspecified IP (0.0.0.0 or ::) with detected external IP.
func replaceUnspecifiedWithExternal(host string) string {
	parsedIP := net.ParseIP(host)
	if parsedIP != nil && parsedIP.IsUnspecified() {
		if ext := detectExternalIP(); ext != "" {
			return ext
		}
	}
	return host
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
	return findBestPublicIP(addrs)
}

// findBestPublicIP searches interface addresses for the best public IP.
// Prefers public IPv4; falls back to any non-private IP if no public IPv4 is
// found. Mirrors ntcp2.findBestExternalIP: RFC 1918 private addresses are never
// used as a fallback, so the two transports advertise consistent endpoints and
// a private bind address is not published as if it were reachable.
func findBestPublicIP(addrs []net.Addr) string {
	var fallback string
	for _, addr := range addrs {
		ip := extractIP(addr)
		if ip == nil || shouldSkipAddress(ip) {
			continue
		}

		if isPublicIPv4Address(ip) {
			return ip.String()
		}

		if fallback == "" && !ip.IsPrivate() {
			fallback = ip.String()
		}
	}
	return fallback
}

// extractIP extracts net.IP from various address types.
func extractIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

// shouldSkipAddress returns true if the IP should be skipped (loopback, link-local, etc.).
func shouldSkipAddress(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// isPublicIPv4Address returns true if the IP is a publicly routable IPv4 address.
// BUG FIX: the previous implementation only checked To4()+IsGlobalUnicast(),
// which treats RFC 1918 private ranges (and CGNAT) as public because Go's
// IsGlobalUnicast() returns true for them. Delegating to the canonical
// classifier in lib/nat ensures private/CGNAT/special-use IPs are correctly
// excluded, matching the NTCP2 and router-status classifiers.
func isPublicIPv4Address(ip net.IP) bool {
	return nat.IsPublicRoutableIPv4(ip)
}

// buildBaseSSU2Options creates the base options map for an SSU2 RouterAddress.
func buildBaseSSU2Options(host, port string) map[string]string {
	return map[string]string{
		router_address.HOST_OPTION_KEY:             host,
		router_address.PORT_OPTION_KEY:             port,
		router_address.PROTOCOL_VERSION_OPTION_KEY: "2",
	}
}

// addIntroKeyOption adds the "i" (introduction key) option to the RouterAddress options.
// The intro key is required by remote routers to obfuscate SSU2 packet headers.
func addIntroKeyOption(options map[string]string, transport *SSU2Transport) {
	ik := transport.GetIntroKey()
	if len(ik) == 32 {
		options[router_address.INITIALIZATION_VECTOR_OPTION_KEY] = encodeBase64(ik)
	}
}

// addStaticKeyOption adds the static key option if configured.
// The SSU2Config.StaticKey contains the X25519 PRIVATE key. The SSU2 spec
// requires publishing the corresponding PUBLIC key as the 's=' parameter.
// This mirrors the NTCP2 pattern in ntcp2/router_address.go.
func addStaticKeyOption(options map[string]string, transport *SSU2Transport) {
	// R-2 fix: Atomic config snapshot
	cfg := transport.config.Load()
	if cfg != nil && cfg.SSU2Config != nil && len(cfg.SSU2Config.StaticKey) == 32 {
		pub, err := curve25519.X25519(cfg.SSU2Config.StaticKey, curve25519.Basepoint)
		if err != nil {
			return
		}
		options[router_address.STATIC_KEY_OPTION_KEY] = encodeBase64(pub)
	}
}

// addIntroducerOptions adds introducer information to the options map.
func addIntroducerOptions(options map[string]string, introducers []*ssu2noise.RegisteredIntroducer) {
	for i, intro := range introducers {
		if i > router_address.MAX_INTRODUCER_NUMBER {
			break
		}
		if intro == nil {
			continue
		}
		addSingleIntroducerOptions(options, intro, i)
	}
}

// addSingleIntroducerOptions adds options for a single introducer.
func addSingleIntroducerOptions(options map[string]string, intro *ssu2noise.RegisteredIntroducer, index int) {
	prefix := fmt.Sprintf("%d", index)
	if len(intro.RouterHash) > 0 {
		options[router_address.INTRODUCER_HASH_PREFIX+prefix] = encodeBase64(intro.RouterHash)
	}
	if intro.RelayTag != 0 {
		options[router_address.INTRODUCER_TAG_PREFIX+prefix] = fmt.Sprintf("%d", intro.RelayTag)
	}
	if !intro.AddedAt.IsZero() {
		expTime := intro.AddedAt.Add(4 * time.Hour).Unix()
		options[router_address.INTRODUCER_EXPIRATION_PREFIX+prefix] = fmt.Sprintf("%d", expTime)
	}
}

// encodeBase64 returns the I2P base64 encoding of data.
func encodeBase64(data []byte) string {
	return i2pbase64.EncodeToString(data)
}

// IntroducerAddr holds the parsed fields of a single SSU2 introducer entry
// from a RouterAddress's options (ih0/itag0/iexp0 through ih2/itag2/iexp2).
type IntroducerAddr struct {
	// RouterHash is Bob's 32-byte router identity hash (from the ih<N> option).
	RouterHash data.Hash

	// RelayTag is the relay tag assigned by Bob to Charlie (from the itag<N> option).
	RelayTag uint32

	// Expiry is the Unix timestamp (seconds) after which the introduction expires.
	Expiry int64
}

// ExtractIntroducers parses the introducer entries (indices 0-2) from a single
// SSU2 RouterAddress, returning all valid entries.  Invalid or missing entries
// (e.g. empty hash, zero relay tag, already-expired) are silently skipped.
func ExtractIntroducers(addr *router_address.RouterAddress) []IntroducerAddr {
	if addr == nil {
		return nil
	}
	now := time.Now().Unix()
	var result []IntroducerAddr
	for i := router_address.MIN_INTRODUCER_NUMBER; i <= router_address.MAX_INTRODUCER_NUMBER; i++ {
		if intro, ok := extractIntroducerAtSlot(addr, i, now); ok {
			result = append(result, intro)
		}
	}
	return result
}

// parseIntroducerHash decodes the base64 router hash from slot in addr.
// Returns a zero Hash and false if the option is absent or malformed.
func parseIntroducerHash(addr *router_address.RouterAddress, slot int) (data.Hash, bool) {
	hashStr, err := addr.IntroducerHashString(slot).Data()
	if err != nil || hashStr == "" {
		return data.Hash{}, false
	}
	hashBytes, err := i2pbase64.DecodeString(hashStr)
	if err != nil || len(hashBytes) != 32 {
		return data.Hash{}, false
	}
	var h data.Hash
	copy(h[:], hashBytes)
	return h, true
}

// parseRelayTag parses the relay tag integer from slot in addr.
// Returns 0, false if the option is absent, malformed, or zero-valued.
func parseRelayTag(addr *router_address.RouterAddress, slot int) (uint32, bool) {
	tagStr, err := addr.IntroducerTagString(slot).Data()
	if err != nil || tagStr == "" {
		return 0, false
	}
	tag64, err := strconv.ParseUint(tagStr, 10, 32)
	if err != nil || tag64 == 0 {
		return 0, false
	}
	return uint32(tag64), true
}

// parseIntroducerExpiry returns the Unix expiry timestamp for slot, or 0 if
// the option is absent or cannot be parsed.
func parseIntroducerExpiry(addr *router_address.RouterAddress, slot int) int64 {
	expStr, err := addr.IntroducerExpirationString(slot).Data()
	if err != nil || expStr == "" {
		return 0
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return 0
	}
	return exp
}

// extractIntroducerAtSlot attempts to parse a single introducer entry at the
// given slot index. Returns the parsed introducer and true if valid, or a zero
// value and false if the entry is missing, malformed, or expired.
func extractIntroducerAtSlot(addr *router_address.RouterAddress, slot int, now int64) (IntroducerAddr, bool) {
	if !addr.CheckOption(router_address.INTRODUCER_HASH_PREFIX + strconv.Itoa(slot)) {
		return IntroducerAddr{}, false
	}
	routerHash, ok := parseIntroducerHash(addr, slot)
	if !ok {
		return IntroducerAddr{}, false
	}
	tag, ok := parseRelayTag(addr, slot)
	if !ok {
		return IntroducerAddr{}, false
	}
	expiry := parseIntroducerExpiry(addr, slot)
	if expiry > 0 && expiry < now {
		return IntroducerAddr{}, false
	}
	return IntroducerAddr{
		RouterHash: routerHash,
		RelayTag:   tag,
		Expiry:     expiry,
	}, true
}

// HasIntroducerOnlySSU2Address returns true if the RouterInfo has at least one
// SSU2 address containing a valid introducer entry (ih0/itag0 present) but no
// directly dialable address.  Used by Compatible() and GetSession() to decide
// whether the introducer path should be attempted.
func HasIntroducerOnlySSU2Address(ri *router_info.RouterInfo) bool {
	if ri == nil {
		return false
	}
	for _, addr := range ri.RouterAddresses() {
		if !isSSU2Transport(addr) {
			continue
		}
		if len(ExtractIntroducers(addr)) > 0 {
			return true
		}
	}
	return false
}
