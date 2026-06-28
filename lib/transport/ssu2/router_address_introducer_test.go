package ssu2

// router_address_introducer_test.go covers Track C3: when the transport's
// listener is bound to a non-public address but at least one usable
// introducer is registered, ConvertToRouterAddress must publish an
// introducer-only RouterAddress (caps=B, no host/port, ih0/itag0/iexp0).

import (
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/router_address"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeUsableIntroducer returns a RegisteredIntroducer with the minimum fields
// required for hasUsableIntroducer to return true and for the registry to
// accept it (keys are 44-byte base64 strings of 32 zero/one bytes).
func makeUsableIntroducer(t testing.TB, relayTag uint32) *ssu2noise.RegisteredIntroducer {
	t.Helper()
	staticKey := make([]byte, 44)
	introKey := make([]byte, 44)
	copy(staticKey, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	copy(introKey, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	return &ssu2noise.RegisteredIntroducer{
		Addr:       &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9001},
		RouterHash: hash,
		StaticKey:  staticKey,
		IntroKey:   introKey,
		RelayTag:   relayTag,
		AddedAt:    time.Now(),
	}
}

// TestIsPublicHost covers the helper used by the introducer-only path.
func TestIsPublicHost(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"100.64.1.1", false},
		{"192.0.2.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"::1", false},
		{"::", false},
		{"", false},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, isPublicHost(c.in), "host=%q", c.in)
	}
}

// TestHasUsableIntroducer covers the helper that decides whether the
// introducer-only path is taken.
func TestHasUsableIntroducer(t *testing.T) {
	assert.False(t, hasUsableIntroducer(nil))
	assert.False(t, hasUsableIntroducer([]*ssu2noise.RegisteredIntroducer{nil}))
	assert.False(t, hasUsableIntroducer([]*ssu2noise.RegisteredIntroducer{{
		RouterHash: make([]byte, 32),
		RelayTag:   0, // missing tag
	}}))
	assert.False(t, hasUsableIntroducer([]*ssu2noise.RegisteredIntroducer{{
		RouterHash: nil, // missing hash
		RelayTag:   42,
	}}))
	assert.True(t, hasUsableIntroducer([]*ssu2noise.RegisteredIntroducer{{
		RouterHash: make([]byte, 32),
		RelayTag:   42,
	}}))
}

// TestConvertToRouterAddress_IntroducerOnly verifies that a transport bound to
// loopback (a non-public host) with at least one registered introducer
// publishes an introducer-only RouterAddress: caps=B, no host/port, and the
// introducer fields ih0/itag0 present.
func TestConvertToRouterAddress_IntroducerOnly(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	require.NoError(t, tr.RegisterIntroducer(makeUsableIntroducer(t, 0xCAFEBABE)))

	ra, err := ConvertToRouterAddress(tr)
	require.NoError(t, err)
	require.NotNil(t, ra)

	// Direct-connection options must be absent.
	assert.False(t, ra.CheckOption(router_address.HOST_OPTION_KEY),
		"host option must be omitted for introducer-only address")
	assert.False(t, ra.CheckOption(router_address.PORT_OPTION_KEY),
		"port option must be omitted for introducer-only address")

	// Caps and version must signal introducer-required mode.
	caps, err := ra.CapsString().Data()
	require.NoError(t, err)
	assert.Equal(t, "B", caps, "caps must be 'B' for introducer-required address")

	ver, err := ra.ProtocolVersionString().Data()
	require.NoError(t, err)
	assert.Equal(t, "2", ver)

	// Introducer slot 0 must be populated (hash + tag).
	assert.True(t, ra.CheckOption(router_address.INTRODUCER_HASH_PREFIX+"0"))
	assert.True(t, ra.CheckOption(router_address.INTRODUCER_TAG_PREFIX+"0"))

	// ExtractIntroducers must round-trip the registered introducer.
	intros := ExtractIntroducers(ra)
	require.Len(t, intros, 1)
	assert.Equal(t, uint32(0xCAFEBABE), intros[0].RelayTag)
}

// TestConvertToRouterAddress_NonPublicNoIntroducers verifies that a transport
// bound to a non-public (RFC1918 / loopback) address with no introducers
// publishes a caps-only SSU2 address (no host/port leaked, caps="4") so that
// the RouterInfo remains spec-conformant. Publishing a private host would
// cause Java I2P / i2pd to reject our entire RouterInfo as malformed and
// silently kill NTCP2 SessionConfirmed, breaking all tunnel builds.
func TestConvertToRouterAddress_NonPublicNoIntroducers(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	ra, err := ConvertToRouterAddress(tr)
	require.NoError(t, err)
	require.NotNil(t, ra)

	assert.False(t, ra.CheckOption(router_address.HOST_OPTION_KEY),
		"host must NOT be published when not publicly routable (private-IP leak guard)")
	assert.False(t, ra.CheckOption(router_address.PORT_OPTION_KEY),
		"port must NOT be published when host is suppressed")
	assert.True(t, ra.CheckOption(router_address.CAPS_OPTION_KEY),
		"caps MUST be set on a caps-only SSU2 fallback to advertise SSU2 capability")
}
