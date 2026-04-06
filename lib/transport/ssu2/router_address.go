package ssu2

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
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

// ssu2IPv6Once / ssu2HasIPv6Support cache the one-time IPv6 connectivity probe
// result for the ssu2 package (mirrors ntcp2.probeIPv6, AUDIT FIX-2 / RC-C).
var (
	ssu2IPv6Once       sync.Once
	ssu2HasIPv6Support bool
)

// probeIPv6 returns true if the host has at least one non-loopback, globally
// unicast IPv6 interface. The result is cached after the first call.
func probeIPv6() bool {
	ssu2IPv6Once.Do(func() {
		ifaces, err := net.Interfaces()
		if err != nil {
			return
		}
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && ip.To4() == nil && ip.IsGlobalUnicast() {
					ssu2HasIPv6Support = true
					return
				}
			}
		}
	})
	return ssu2HasIPv6Support
}

// ExtractSSU2Addr extracts the SSU2 network address from a RouterInfo structure.
// It returns a *net.UDPAddr for the best SSU2 transport address found, using a
// two-pass strategy: IPv4 addresses are preferred; IPv6 is only returned when
// the host has confirmed global-unicast IPv6 connectivity (AUDIT FIX-2 / RC-C).
func ExtractSSU2Addr(routerInfo router_info.RouterInfo) (*net.UDPAddr, error) {
	var ipv6Fallback *net.UDPAddr
	for _, addr := range routerInfo.RouterAddresses() {
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
			return udpAddr, nil
		}
		// IPv6 — only keep if the local host has IPv6 connectivity.
		if ipv6Fallback == nil && probeIPv6() {
			ipv6Fallback = udpAddr
		}
	}
	if ipv6Fallback != nil {
		return ipv6Fallback, nil
	}
	return nil, ErrInvalidRouterInfo
}

// ExtractSSU2IntroKey extracts the 32-byte introduction key from the "i" option
// of the first SSU2 RouterAddress found in ri.  The option value is
// I2P-base64-encoded (same alphabet as static keys).
// Returns an error if no SSU2 address carries a valid 32-byte intro key.
func ExtractSSU2IntroKey(ri router_info.RouterInfo) ([]byte, error) {
	for _, addr := range ri.RouterAddresses() {
		if !isSSU2Transport(addr) {
			continue
		}
		ivStr := addr.InitializationVectorString()
		if ivStr == nil {
			continue
		}
		encoded, err := ivStr.Data()
		if err != nil {
			continue
		}
		raw, err := i2pbase64.DecodeString(encoded)
		if err != nil {
			continue
		}
		if len(raw) != 32 {
			continue
		}
		return raw, nil
	}
	return nil, fmt.Errorf("no SSU2 address with a 32-byte intro key found in RouterInfo")
}

// resolveUDPAddress extracts host and port from a RouterAddress and resolves to a UDP address.
func resolveUDPAddress(addr *router_address.RouterAddress) (*net.UDPAddr, error) {
	host, err := addr.Host()
	if err != nil {
		return nil, fmt.Errorf("failed to extract host: %w", err)
	}

	port, err := addr.Port()
	if err != nil {
		return nil, fmt.Errorf("failed to extract port: %w", err)
	}

	hostStr := host.String()
	// addr.Host() returns a net.Addr; extract the IP portion
	if h, _, splitErr := net.SplitHostPort(hostStr); splitErr == nil {
		hostStr = h
	}

	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(hostStr, port))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}
	return udpAddr, nil
}

// ConvertToRouterAddress converts an SSU2Transport's listening address to a RouterAddress
// suitable for publishing in RouterInfo.
func ConvertToRouterAddress(transport *SSU2Transport) (*router_address.RouterAddress, error) {
	if transport == nil {
		return nil, fmt.Errorf("transport cannot be nil")
	}

	addr := transport.Addr()
	if addr == nil {
		return nil, fmt.Errorf("transport has no listener address")
	}

	host, portStr, err := extractHostPort(addr)
	if err != nil {
		return nil, err
	}

	options := buildBaseSSU2Options(host, portStr)
	addStaticKeyOption(options, transport)
	addIntroKeyOption(options, transport)
	addIntroducerOptions(options, transport.GetIntroducers())

	ra, err := router_address.NewRouterAddress(0, time.Time{}, "SSU2", options)
	if err != nil {
		return nil, fmt.Errorf("failed to create RouterAddress: %w", err)
	}
	return ra, nil
}

// extractHostPort unwraps SSU2Addr and extracts host and port from the listener address.
func extractHostPort(addr net.Addr) (string, string, error) {
	effectiveAddr := addr
	if ssu2Addr, ok := addr.(*ssu2noise.SSU2Addr); ok {
		effectiveAddr = ssu2Addr.UnderlyingAddr()
	}
	host, portStr, err := net.SplitHostPort(effectiveAddr.String())
	if err != nil {
		return "", "", fmt.Errorf("failed to parse listener address: %w", err)
	}
	return host, portStr, nil
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
func addStaticKeyOption(options map[string]string, transport *SSU2Transport) {
	if transport.config != nil && transport.config.SSU2Config != nil && len(transport.config.SSU2Config.StaticKey) == 32 {
		options[router_address.STATIC_KEY_OPTION_KEY] = encodeBase64(transport.config.SSU2Config.StaticKey)
	}
}

// addIntroducerOptions adds introducer information to the options map.
func addIntroducerOptions(options map[string]string, introducers []*ssu2noise.RegisteredIntroducer) {
	for i, intro := range introducers {
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
		hashStr, err := addr.IntroducerHashString(i).Data()
		if err != nil || hashStr == "" {
			continue
		}
		hashBytes, err := i2pbase64.DecodeString(hashStr)
		if err != nil || len(hashBytes) != 32 {
			continue
		}
		tagStr, err := addr.IntroducerTagString(i).Data()
		if err != nil || tagStr == "" {
			continue
		}
		tag64, err := strconv.ParseUint(tagStr, 10, 32)
		if err != nil || tag64 == 0 {
			continue
		}

		var expiry int64
		if expStr, err2 := addr.IntroducerExpirationString(i).Data(); err2 == nil && expStr != "" {
			if exp, err3 := strconv.ParseInt(expStr, 10, 64); err3 == nil {
				expiry = exp
			}
		}
		if expiry > 0 && expiry < now {
			continue // already expired
		}

		var routerHash data.Hash
		copy(routerHash[:], hashBytes)
		result = append(result, IntroducerAddr{
			RouterHash: routerHash,
			RelayTag:   uint32(tag64),
			Expiry:     expiry,
		})
	}
	return result
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
