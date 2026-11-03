// Tests for pre-authentication inbound handshake admission control (H-033).
//
// Finding 004 left the router's only reachable inbound surface being the
// unauthenticated handshake: each accepted TCP connection cost a goroutine, a
// socket and the handshake's own buffers, with no bound on how many could be
// outstanding at once. These tests pin the two bounds that were added: the
// transport-wide cap and the per-source cap, including that a refusal closes the
// connection and never spawns a handshake.

package ntcp2

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandshakeAdmission_GlobalCapBoundsConcurrentHandshakes verifies the
// transport-wide budget: exactly global handshakes may be in flight, no more,
// and the budget is returned when a handshake releases its slot.
func TestHandshakeAdmission_GlobalCapBoundsConcurrentHandshakes(t *testing.T) {
	a := newHandshakeAdmission()
	const global = 3

	releases := make([]func(), 0, global)
	for i := 0; i < global; i++ {
		release, err := a.admit(&net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 1000 + i}, global, -1)
		require.NoError(t, err, "handshake %d within the budget must be admitted", i)
		releases = append(releases, release)
	}
	assert.EqualValues(t, global, a.current(), "all slots accounted as in flight")

	// Budget spent: the next connection is refused, not queued.
	release, err := a.admit(&net.TCPAddr{IP: net.ParseIP("203.0.113.2"), Port: 2000}, global, -1)
	assert.ErrorIs(t, err, errAdmissionGlobalFull, "connection beyond the budget must be refused")
	release() // must be safe to call on a refusal

	// Freeing one slot admits exactly one more.
	releases[0]()
	releases[0] = func() {} // don't release twice at cleanup
	assert.EqualValues(t, global-1, a.current(), "released slot returned to the budget")

	release, err = a.admit(&net.TCPAddr{IP: net.ParseIP("203.0.113.3"), Port: 3000}, global, -1)
	require.NoError(t, err, "a freed slot must admit the next connection")
	releases = append(releases, release)

	for _, r := range releases {
		r()
	}
	assert.Zero(t, a.current(), "budget fully returned after all releases")
}

// TestHandshakeAdmission_PerSourceCapStopsOneHostConsumingBudget verifies that a
// single source cannot occupy the whole transport-wide budget, which is the
// per-IP half of H-033. The global cap is deliberately larger here so that only
// the per-source bound can be what refuses.
func TestHandshakeAdmission_PerSourceCapStopsOneHostConsumingBudget(t *testing.T) {
	a := newHandshakeAdmission()
	const global = 100
	const perSource = 4

	host := net.ParseIP("198.51.100.7")
	releases := make([]func(), 0, perSource)
	for i := 0; i < perSource; i++ {
		release, err := a.admit(&net.TCPAddr{IP: host, Port: 5000 + i}, global, perSource)
		require.NoError(t, err, "connection %d from the source must be admitted", i)
		releases = append(releases, release)
	}
	assert.Equal(t, perSource, a.sourceCount(&net.TCPAddr{IP: host, Port: 0}),
		"all of the source's handshakes counted under one key regardless of port")

	// Same host, different port: still the same source, so still refused.
	release, err := a.admit(&net.TCPAddr{IP: host, Port: 6000}, global, perSource)
	assert.ErrorIs(t, err, errAdmissionSourceFull,
		"a fifth handshake from the same source must be refused while the global budget is free")
	release()

	// A different host is unaffected by the first host's saturation.
	release, err = a.admit(&net.TCPAddr{IP: net.ParseIP("198.51.100.8"), Port: 7000}, global, perSource)
	require.NoError(t, err, "another source must still be admitted")
	release()

	for _, r := range releases {
		r()
	}
	assert.Zero(t, a.current(), "global budget fully returned")
	assert.Zero(t, a.sourceCount(&net.TCPAddr{IP: host, Port: 0}),
		"the source's map entry must be deleted so the map cannot grow without bound")
}

// TestHandshakeAdmission_SourceKeyIgnoresPortAndUnwrapsNTCP2Addr pins the keying
// rule: two connections from one host are one source even though NTCP2 reports a
// distinct address per connection, and the *ntcp2.Addr wrapper (whose String()
// embeds a pre-handshake placeholder router hash) is unwrapped rather than
// stringified.
func TestHandshakeAdmission_SourceKeyIgnoresPortAndUnwrapsNTCP2Addr(t *testing.T) {
	tcp := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4242}
	other := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 9999}
	require.Equal(t, handshakeSourceKey(tcp), handshakeSourceKey(other),
		"same IP, different port must be one source")

	wrapped, err := ntcp2.NewNTCP2Addr(tcp, newTestRouterHash(1), "responder")
	require.NoError(t, err)
	require.NotEqual(t, wrapped.String(), tcp.String(), "the NTCP2 wrapper must carry extra text")
	assert.Equal(t, handshakeSourceKey(tcp), handshakeSourceKey(wrapped),
		"an *ntcp2.Addr must key on the underlying TCP address's IP")

	// A non-IP address still keys on something stable rather than being dropped.
	assert.Equal(t, "pipe-1", handshakeSourceKey(&mockAddr{"pipe-1"}))
	assert.Empty(t, handshakeSourceKey(nil), "a nil address must not panic")
}

// TestAdmitInboundHandshake_RefusedConnectionClosesWithoutHandshake is the
// regression test for the pre-auth cost in finding 004: a connection that
// arrives while the handshake budget is spent must be closed immediately and
// must never reach the handshake path, so it costs no goroutine, no 60s
// handshake window, and no probing-resistance junk read.
func TestAdmitInboundHandshake_RefusedConnectionClosesWithoutHandshake(t *testing.T) {
	transport := newTestTransport(newMockListener(), 10)
	transport.admission = newHandshakeAdmission()

	// One handshake allowed transport-wide, per-source bound off so the global
	// bound is what refuses.
	setAdmissionLimits(t, transport, 1, -1)

	// An admitted connection yields a release and is left open.
	allowed := newAcceptMockConn("10.0.0.3:5556")
	release := transport.admitInboundHandshake(allowed)
	require.NotNil(t, release, "a connection within the budget must be admitted")
	assert.False(t, mockConnClosed(allowed), "an admitted connection must stay open")
	assert.Zero(t, transport.metrics.handshakeRefusedGlobal.Load())

	// Budget now spent: the next connection is refused outright.
	refused := newAcceptMockConn("10.0.0.2:5555")
	refusedRelease := transport.admitInboundHandshake(refused)
	assert.Nil(t, refusedRelease, "a refused connection must not yield a release function")
	assert.True(t, mockConnClosed(refused), "a refused connection must be closed at once")
	assert.EqualValues(t, 1, transport.metrics.handshakeRefusedGlobal.Load(),
		"the refusal must be counted for alerting")
	assert.EqualValues(t, 0, transport.GetSessionCount(),
		"refusing a connection must not consume a session slot")
	assert.EqualValues(t, 1, transport.admission.current(),
		"refusal must not disturb the in-flight accounting")

	// Releasing the admitted slot returns the budget.
	release()
	assert.Zero(t, transport.admission.current(), "release returns the slot")

	// Calling release twice must not over-return the budget.
	release()
	assert.Zero(t, transport.admission.current())
}

// TestAdmitInboundHandshake_DisablingBoundsAdmitsEverything verifies that a
// negative limit means "no bound", so an operator who wants the pre-handshake
// path unrestricted can turn it off explicitly rather than by leaving it unset.
func TestAdmitInboundHandshake_DisablingBoundsAdmitsEverything(t *testing.T) {
	transport := newTestTransport(newMockListener(), 10)
	transport.admission = newHandshakeAdmission()
	setAdmissionLimits(t, transport, -1, -1)

	for i := 0; i < 50; i++ {
		conn := newAcceptMockConn("10.0.0.4:1000")
		release := transport.admitInboundHandshake(conn)
		require.NotNilf(t, release, "connection %d must be admitted when bounds are disabled", i)
		assert.False(t, mockConnClosed(conn))
		release()
	}
	assert.Zero(t, transport.admission.current(), "disabled bounds must not leak reservations")
	assert.Zero(t, transport.metrics.handshakeRefusedGlobal.Load())
	assert.Zero(t, transport.metrics.handshakeRefusedSource.Load())
}

// TestAcceptNextConnection_SurplusConnectionsShedAtAccept drives the real accept
// path with more connections than the budget allows and proves every surplus
// connection is closed at accept time instead of being handed a handshake
// goroutine. This is the shape of the finding 004 pre-auth exhaustion: many
// simultaneous connections from one host.
func TestAcceptNextConnection_SurplusConnectionsShedAtAccept(t *testing.T) {
	const global = 2
	const total = 10

	ln := newMockListener()
	transport := newTestTransport(ln, 10)
	transport.admission = newHandshakeAdmission()
	setAdmissionLimits(t, transport, global, -1)

	// Occupy the whole budget up front, standing in for the handshakes the flood
	// is allowed. They are released at the end of the test.
	holders := make([]func(), 0, global)
	for i := 0; i < global; i++ {
		release, err := transport.admission.admit(
			&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1000 + i}, global, -1)
		require.NoError(t, err)
		holders = append(holders, release)
	}

	conns := make([]*acceptMockConn, 0, total)
	for i := 0; i < total; i++ {
		c := newAcceptMockConn("127.0.0.1:4000")
		conns = append(conns, c)
		ln.conns <- c
	}

	// Run the accept path exactly as runInboundAcceptLoop would, one connection
	// per iteration. No handshake worker may be spawned for any of them.
	for i := 0; i < total; i++ {
		require.True(t, transport.acceptNextConnection(), "accept loop must keep running")
	}

	for i, c := range conns {
		assert.Truef(t, mockConnClosed(c),
			"connection %d beyond the handshake budget must be closed at accept time", i)
	}
	assert.EqualValues(t, global, transport.admission.current(),
		"shed connections must not alter the in-flight accounting")

	snapshot := transport.GetTransportMetrics()
	assert.EqualValues(t, total, snapshot.HandshakeRefusedGlobal,
		"every shed connection must be reflected in the refusal metric")
	assert.EqualValues(t, 0, transport.GetSessionCount(),
		"shedding pre-auth connections must not consume session slots")

	for _, h := range holders {
		h()
	}
	assert.Zero(t, transport.admission.current(), "budget fully returned")

	// With the budget free again, a connection is admitted rather than shed.
	admitted := newAcceptMockConn("127.0.0.1:4100")
	ln.conns <- admitted
	require.True(t, transport.acceptNextConnection())
	require.Eventually(t, func() bool { return transport.admission.current() == 1 },
		2*time.Second, 10*time.Millisecond,
		"an in-budget connection must be admitted to a handshake")
	assert.False(t, mockConnClosed(admitted), "an admitted connection must not be closed at accept time")
}

// mockConnClosed reports whether an acceptMockConn has been closed.
func mockConnClosed(c *acceptMockConn) bool {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return c.closed
}

// setAdmissionLimits replaces the transport's configured handshake bounds, since
// admission reads them from the live config on every call.
func setAdmissionLimits(t *testing.T, transport *NTCP2Transport, global, perSource int) {
	t.Helper()
	cfg := transport.config.Load()
	require.NotNil(t, cfg)
	newCfg := *cfg
	newCfg.MaxInflightHandshakes = global
	newCfg.MaxHandshakesPerSource = perSource
	transport.config.Store(&newCfg)
}

// TestConfig_HandshakeDefaultsAndOverrides pins the documented defaulting rule:
// unset means the default, negative means disabled.
func TestConfig_HandshakeDefaultsAndOverrides(t *testing.T) {
	cfg, err := NewConfig("127.0.0.1:0")
	require.NoError(t, err)

	assert.Equal(t, DefaultMaxInflightHandshakes, cfg.GetMaxInflightHandshakes(),
		"unset global limit must select the default")
	assert.Equal(t, DefaultMaxHandshakesPerSource, cfg.GetMaxHandshakesPerSource(),
		"unset per-source limit must select the default")
	assert.Less(t, cfg.GetMaxHandshakesPerSource(), cfg.GetMaxInflightHandshakes(),
		"one source must not be able to spend the whole budget")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	_ = ctx

	cfg.MaxInflightHandshakes = -1
	cfg.MaxHandshakesPerSource = -1
	assert.Equal(t, -1, cfg.GetMaxInflightHandshakes(), "a negative limit means disabled")
	assert.Equal(t, -1, cfg.GetMaxHandshakesPerSource(), "a negative limit means disabled")

	cfg.MaxInflightHandshakes = 7
	cfg.MaxHandshakesPerSource = 2
	assert.Equal(t, 7, cfg.GetMaxInflightHandshakes())
	assert.Equal(t, 2, cfg.GetMaxHandshakesPerSource())
}

// TestNewNTCP2Transport_EnforcesConfiguredHandshakeBounds is the end-to-end pin
// for the operator-facing settings: limits placed on the Config handed to
// NewNTCP2Transport must actually shed connections on the live accept path. A
// transport that reads its own defaults regardless of what it was constructed
// with would pass every unit test here and still ignore config.yaml.
func TestNewNTCP2Transport_EnforcesConfiguredHandshakeBounds(t *testing.T) {
	const configuredGlobal = 3

	staticPriv := make([]byte, 32)
	for i := range staticPriv {
		staticPriv[i] = byte(i + 1)
	}

	_, port, err := net.SplitHostPort("127.0.0.1:0")
	require.NoError(t, err)

	cfg, err := NewConfig("127.0.0.1:0")
	require.NoError(t, err)
	cfg.MaxInflightHandshakes = configuredGlobal
	cfg.MaxHandshakesPerSource = -1 // isolate the transport-wide bound

	identity := newFallbackIntegrationIdentity(t, "localhost", port, staticPriv)
	keystore := &fallbackIntegrationKeystore{privateKey: append([]byte(nil), staticPriv...)}
	tr, err := NewNTCP2Transport(identity, cfg, keystore)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Close() })

	// The transport must be running the configured numbers, not its defaults.
	live := tr.config.Load()
	require.NotNil(t, live)
	require.Equal(t, configuredGlobal, live.GetMaxInflightHandshakes(),
		"NewNTCP2Transport must carry the configured global handshake bound")

	// Drive the accept path past that bound. admitInboundHandshake is exactly what
	// acceptNextConnection calls before spawning a handshake goroutine.
	conns := make([]*acceptMockConn, 0, configuredGlobal+5)
	for i := 0; i < configuredGlobal+5; i++ {
		conns = append(conns, newAcceptMockConn("10.9.9.9:4000"))
	}

	// Admitted slots are held open (not released) so the budget stays spent and
	// the surplus is what gets refused -- the shape of a real flood, where each
	// handshake is still in flight.
	admitted, shed := 0, 0
	var releases []func()
	for _, c := range conns {
		release := tr.admitInboundHandshake(c)
		if release == nil {
			shed++
			continue
		}
		admitted++
		releases = append(releases, release)
	}
	t.Cleanup(func() {
		for _, r := range releases {
			r()
		}
	})

	assert.Equal(t, configuredGlobal, admitted,
		"exactly the configured number of handshakes may be admitted at once")
	assert.Equal(t, len(conns)-configuredGlobal, shed,
		"every connection beyond the configured bound must be shed")
	assert.EqualValues(t, len(conns)-configuredGlobal,
		tr.GetTransportMetrics().HandshakeRefusedGlobal)
}
