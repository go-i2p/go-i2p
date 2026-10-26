package ssu2

import (
	"strings"
	"testing"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/common/router_address"
)

func emptyIntroducerTransport(t *testing.T) *SSU2Transport {
	t.Helper()
	tr := &SSU2Transport{natStateCache: &natState{}, logger: testLogger()}
	tr.config.Store(&Config{WorkingDir: t.TempDir()})
	return tr
}

// TestPublishedAddressHostPortAndIntroducersAreMutuallyExclusive locks
// ssu2.rst:5719 "A router must not publish host or port in the address when
// publishing introducers."
//
// A publicly routable host is dialable directly, which is the only thing
// published introducers buy a router, so the conformant resolution is to drop
// the introducer hints from that branch rather than drop host/port (which would
// cost a reachable router its inbound connectivity).
func TestPublishedAddressHostPortAndIntroducersAreMutuallyExclusive(t *testing.T) {
	tr := emptyIntroducerTransport(t)
	intros := []*ssu2noise.RegisteredIntroducer{makeUsableIntroducer(t, 7)}

	// Publicly routable host: host+port published, no introducer options.
	pub := buildSSU2Options("8.8.8.8", "8888", tr, intros)
	require.Equal(t, "8.8.8.8", pub[router_address.HOST_OPTION_KEY],
		"a publicly routable host must still be published so peers can dial us")
	assert.Equal(t, "8888", pub[router_address.PORT_OPTION_KEY])
	assert.NotContains(t, pub, router_address.INTRODUCER_HASH_PREFIX+"0",
		"introducers must not be published alongside host/port (ssu2.rst:5719)")
	assert.NotContains(t, pub, router_address.INTRODUCER_TAG_PREFIX+"0")

	// Firewalled host with introducers: introducers published, no host/port.
	fw := buildSSU2Options("10.0.0.5", "8888", tr, intros)
	assert.NotContains(t, fw, router_address.HOST_OPTION_KEY,
		"host must be absent when introducers are published")
	assert.NotContains(t, fw, router_address.PORT_OPTION_KEY,
		"port must be absent when introducers are published")
	assert.Contains(t, fw, router_address.INTRODUCER_HASH_PREFIX+"0",
		"the introducer must be published so peers can reach us through it")

	// Every published branch satisfies the MUST.
	for name, opts := range map[string]map[string]string{
		"public":     pub,
		"firewalled": fw,
		"hidden":     buildSSU2Options("10.0.0.5", "8888", tr, nil),
	} {
		hasHostPort := opts[router_address.HOST_OPTION_KEY] != "" ||
			opts[router_address.PORT_OPTION_KEY] != ""
		hasIntro := opts[router_address.INTRODUCER_HASH_PREFIX+"0"] != ""
		assert.False(t, hasHostPort && hasIntro,
			"%s branch publishes both host/port and introducers", name)
	}
}

// TestIntroducerAddressCarriesFamilyCaps locks ssu2.rst:5720-5721 "A router must
// publish 4 and/or 6 caps in the address when publishing introducers".
func TestIntroducerAddressCarriesFamilyCaps(t *testing.T) {
	tr := emptyIntroducerTransport(t)
	intros := []*ssu2noise.RegisteredIntroducer{makeUsableIntroducer(t, 7)}

	for _, host := range []string{"10.0.0.5", "fd00::1", "not-an-ip", ""} {
		opts := buildSSU2Options(host, "8888", tr, intros)
		if opts[router_address.INTRODUCER_HASH_PREFIX+"0"] == "" {
			continue // branch did not publish introducers, rule does not apply
		}
		caps := opts[router_address.CAPS_OPTION_KEY]
		assert.True(t, strings.Contains(caps, "4") || strings.Contains(caps, "6"),
			"caps %q for host %q must contain 4 and/or 6 (ssu2.rst:5720)", caps, host)
		assert.Contains(t, caps, "B", "an introducer-published address must be firewalled")
	}
}
