package ntcp2

import (
	"strconv"
	"strings"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/samber/oops"
)

// NTCP2 RouterAddress option validation.
//
// Spec: ntcp2.rst:1861-1862 — "Alice must verify that all three options are
// present and valid before connecting using the NTCP2 protocol." The three
// options are s= (static key, :1840-1845), i= (obfuscation IV, :1847-1851)
// and v= (version, :1853-1860).
//
// Version validation (ntcp2.rst:1853-1860):
//   - the current version is 2;
//   - future support is signalled with comma-separated values, e.g. v=2,3;
//   - comma-separated versions must be in numerical (ascending) order;
//   - "When published as \"NTCP\", additional support for version 1 is
//     implied" — v= on an NTCP-published address may therefore list 1 as
//     well, but NTCP2 itself requires version 2 to be among them.
//
// Base64 tolerance (interop):
//
// The spec (:1842, :1849) says the values use "the standard I2P Base 64
// alphabet", which includes '=' padding. In practice i2pd and several Java
// router builds publish the s= and i= options unpadded (Java's Base64 encoding
// has been lenient about padding since 0.9.14, and the reference guidance for
// parsers is to accept both). The shared common/router_address decoder only
// tries the padded alphabet (decodeOptionValue,
// common/router_address/router_address_methods.go:604-620), so unpadded values
// are rejected there and would break dialing those peers. decodeI2PBase64
// below accepts padded and unpadded input alike. (Reported upstream as a
// defect in common/router_address.)

// ntcp2SupportedVersions lists the NTCP2 protocol versions this router can
// speak. Only version 2 exists today (ntcp2.rst:1853).
var ntcp2SupportedVersions = []int{2}

// ValidateNTCP2AddressOptions verifies that a RouterAddress published as
// NTCP2 (or NTCP with NTCP2 options, see isNTCP2DialAddress) carries all
// three NTCP2 options — s=, i= and v= — and that each is valid, per
// ntcp2.rst:1861-1862. It returns the decoded static key and IV on success so
// callers do not decode twice.
func ValidateNTCP2AddressOptions(addr *router_address.RouterAddress) (staticKey, iv []byte, err error) {
	if addr == nil {
		return nil, nil, oops.Errorf("nil NTCP2 router address")
	}

	// v= must be present and valid.
	versionStr, err := addr.ProtocolVersion()
	if err != nil {
		return nil, nil, oops.Wrapf(err, "NTCP2 address is missing the v= option")
	}
	if err := ValidateNTCP2VersionList(versionStr); err != nil {
		return nil, nil, err
	}

	// s= must be present, decode (padded or unpadded I2P base64) to 32 bytes,
	// and be a valid curve point (ntcp2.rst:298).
	staticKey, err = decodeNTCP2AddressOption(addr, "s", 32)
	if err != nil {
		return nil, nil, err
	}
	validated, err := ValidateNTCP2StaticKey(staticKey)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "NTCP2 address s= option")
	}

	// i= must be present and decode to 16 bytes.
	iv, err = decodeNTCP2AddressOption(addr, "i", 16)
	if err != nil {
		return nil, nil, err
	}

	return validated, iv, nil
}

// ValidateNTCP2VersionList validates a v= option value: a comma-separated
// list of version numbers in ascending numerical order (ntcp2.rst:1856-1860),
// at least one of which this router supports.
func ValidateNTCP2VersionList(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return oops.Errorf("NTCP2 v= option is empty")
	}
	parts := strings.Split(v, ",")
	prev := -1
	supported := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return oops.Errorf("NTCP2 v= option %q contains invalid version %q", v, part)
		}
		if n <= prev {
			return oops.Errorf("NTCP2 v= option %q is not in ascending numerical order", v)
		}
		prev = n
		for _, sv := range ntcp2SupportedVersions {
			if n == sv {
				supported = true
			}
		}
	}
	if !supported {
		return oops.Errorf("NTCP2 v= option %q does not include a supported version", v)
	}
	return nil
}

// decodeNTCP2AddressOption extracts the s= or i= option from addr using the
// typed option accessors and decodes it as I2P base64 (padded or unpadded),
// requiring exactly expectedLen bytes.
func decodeNTCP2AddressOption(addr *router_address.RouterAddress, key string, expectedLen int) ([]byte, error) {
	var opt data.I2PString
	switch key {
	case "s":
		opt = addr.StaticKeyString()
	case "i":
		opt = addr.InitializationVectorString()
	default:
		return nil, oops.Errorf("unknown NTCP2 address option %q", key)
	}
	if opt == nil {
		return nil, oops.Errorf("NTCP2 address is missing the %s= option", key)
	}
	value, err := opt.Data()
	if err != nil {
		return nil, oops.Wrapf(err, "NTCP2 address %s= option is unreadable", key)
	}
	decoded, err := decodeI2PBase64(value)
	if err != nil {
		return nil, oops.Wrapf(err, "NTCP2 address %s= option is not valid I2P base64", key)
	}
	if len(decoded) != expectedLen {
		return nil, oops.Errorf("NTCP2 address %s= option decodes to %d bytes, expected %d", key, len(decoded), expectedLen)
	}
	return decoded, nil
}

// decodeI2PBase64 decodes an I2P-base64 string tolerantly: both the padded
// alphabet (what the spec publishes, ntcp2.rst:1842) and the unpadded form
// (what i2pd and lenient Java builds publish) are accepted. It delegates to
// the existing common/base64 decoders — no local alphabet implementation.
func decodeI2PBase64(s string) ([]byte, error) {
	if data, err := i2pbase64.DecodeString(s); err == nil {
		return data, nil
	}
	data, err := i2pbase64.DecodeStringNoPadding(s)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to decode I2P base64 (padded or unpadded)")
	}
	return data, nil
}

// isNTCP2DialAddress reports whether a RouterAddress should be considered as
// an NTCP2 dial candidate.
//
// Beyond addresses published as "NTCP2", ntcp2.rst:1864-1867 says: "When
// published as \"NTCP\" with \"s\", \"i\", and \"v\" options, the router must
// accept incoming connections on that host and port for both NTCP and NTCP2
// protocols, and automatically detect the protocol version." A conforming
// router therefore signals NTCP2 reachability on that host:port by publishing
// an "NTCP" address carrying the full set of NTCP2 options.
//
// Conservative reading implemented here: an "NTCP" address qualifies as an
// NTCP2 dial candidate only when all three options are present AND valid
// (ValidateNTCP2AddressOptions). Rationale:
//   - the spec text conditions the dual-protocol behaviour on the presence of
//     "s", "i", and "v" options; an NTCP address without them is legacy-
//     NTCP-only and must not be dialed as NTCP2;
//   - ntcp2.rst:1873-1881 requires routers without auto-detection to publish
//     the NTCP2 options in the "NTCP2" address only, so an NTCP address with
//     full valid NTCP2 options can only come from a router that does support
//     NTCP2 on that port;
//   - dialing NTCP2 against such an address is the compatible action for this
//     router even though we do not implement legacy NTCP or inbound
//     auto-detection ourselves.
func isNTCP2DialAddress(addr *router_address.RouterAddress) bool {
	if addr == nil {
		return false
	}
	if isNTCP2Transport(addr) {
		return true
	}
	style := addr.TransportStyle()
	str, err := style.Data()
	if err != nil || !strings.EqualFold(strings.TrimSpace(str), "ntcp") {
		return false
	}
	_, _, err = ValidateNTCP2AddressOptions(addr)
	return err == nil
}
