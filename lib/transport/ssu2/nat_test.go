package ssu2

import (
	"context"
	"crypto/rand"
	"net"
	"testing"

	"github.com/go-i2p/common/data"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestListener creates a minimal SSU2Listener on an ephemeral loopback
// UDP port for use in NAT manager unit tests.
func makeTestListener(t testing.TB) (*ssu2noise.SSU2Listener, func()) {
	t.Helper()
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	var routerHashArr data.Hash
	copy(routerHashArr[:], routerHash)
	cfg, err := ssu2noise.NewSSU2Config(routerHashArr, false)
	require.NoError(t, err)
	priv := make([]byte, 32)
	_, err = rand.Read(priv)
	require.NoError(t, err)
	cfg = cfg.WithStaticKey(priv)
	// Add RouterInfoValidator required for responder configs per SSU2 spec
	cfg.RouterInfoValidator = func(routerInfo, authenticatedStaticKey []byte) error {
		return nil // Accept any RouterInfo in tests
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	l, err := ssu2noise.NewSSU2Listener(udpConn, cfg)
	require.NoError(t, err)
	require.NoError(t, l.Start())

	cleanup := func() {
		l.Close()
		udpConn.Close()
	}
	return l, cleanup
}

// makeTestTransportWithListener constructs an SSU2Transport with real NAT
// managers but without a real router identity (for unit testing only).
func makeTestTransportWithListener(t testing.TB) (*SSU2Transport, func()) {
	t.Helper()
	l, listenerCleanup := makeTestListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	tr := &SSU2Transport{
		listener: l,
		logger:   log.WithField("test", "nat"),
		ctx:      ctx,
		cancel:   cancel,
		config:   &Config{ListenerAddress: ":0", MaxSessions: 4},
		handler:  NewDefaultHandler(),
	}
	initNATManagers(tr)
	cleanup := func() {
		cancel()
		listenerCleanup()
	}
	return tr, cleanup
}

// TestInitNATManagers verifies that initNATManagers allocates all four
// managers without panicking.
func TestInitNATManagers(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	assert.NotNil(t, tr.peerTestManager, "peerTestManager should be set")
	assert.NotNil(t, tr.relayManager, "relayManager should be set")
	assert.NotNil(t, tr.introducerRegistry, "introducerRegistry should be set")
	assert.NotNil(t, tr.holePunchCoord, "holePunchCoord should be set")
}

// TestInitiateNATDetection verifies that InitiateNATDetection returns a
// non-zero nonce and records an in-progress peer test entry.
func TestInitiateNATDetection(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	bob := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 29001}
	nonce, err := tr.InitiateNATDetection(bob)
	require.NoError(t, err)
	assert.NotZero(t, nonce)

	pt := tr.peerTestManager.GetTest(nonce)
	require.NotNil(t, pt, "test should be registered after InitiateNATDetection")
}

// TestGetNATType_NoResult returns NATUnknown when no test has completed.
func TestGetNATType_NoResult(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9000}
	assert.Equal(t, ssu2noise.NATUnknown, tr.GetNATType(addr))
}

// TestGetExternalAddr_NoResult returns nil when no test has completed.
func TestGetExternalAddr_NoResult(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9000}
	assert.Nil(t, tr.GetExternalAddr(addr))
}

// TestRegisterAndGetIntroducers round-trips a RegisteredIntroducer through the
// IntroducerRegistry.
func TestRegisterAndGetIntroducers(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	// StaticKey and IntroKey must be exactly 44 bytes (base64-encoded 32-byte keys).
	staticKey := make([]byte, 44)
	introKey := make([]byte, 44)
	copy(staticKey, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // placeholder 44 bytes
	copy(introKey, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==")  // placeholder 44 bytes

	intro := &ssu2noise.RegisteredIntroducer{
		Addr:       &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9003},
		RouterHash: make([]byte, 32),
		StaticKey:  staticKey,
		IntroKey:   introKey,
		RelayTag:   0xDEADBEEF,
	}
	err := tr.RegisterIntroducer(intro)
	require.NoError(t, err)

	introList := tr.GetIntroducers()
	require.Len(t, introList, 1)
	assert.Equal(t, uint32(0xDEADBEEF), introList[0].RelayTag)
}

// TestAllocateRelayTag verifies relay-tag allocation returns a non-zero tag.
func TestAllocateRelayTag(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 9004}
	tag, err := tr.AllocateRelayTag(addr)
	require.NoError(t, err)
	assert.NotZero(t, tag)
}

// TestBuildTransportCallbacks verifies that buildTransportCallbacks returns
// non-nil handlers for relay and peer-test block types.
func TestBuildTransportCallbacks(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	cfg := tr.buildTransportCallbacks(nil)
	require.NotNil(t, cfg)
	assert.NotNil(t, cfg.OnPeerTest, "OnPeerTest should be set")
	assert.NotNil(t, cfg.OnRelayRequest, "OnRelayRequest should be set")
	assert.NotNil(t, cfg.OnRelayResponse, "OnRelayResponse should be set")
	assert.NotNil(t, cfg.OnRelayIntro, "OnRelayIntro should be set")
}

// TestNATMethods_NoManagers checks that NAT methods return gracefully when
// the transport has no managers (unstarted / zero-value transport).
func TestNATMethods_NoManagers(t *testing.T) {
	tr := &SSU2Transport{}

	_, err := tr.InitiateNATDetection(&net.UDPAddr{})
	assert.ErrorIs(t, err, ErrTransportNotStarted)

	assert.Equal(t, ssu2noise.NATUnknown, tr.GetNATType(&net.UDPAddr{}))
	assert.Nil(t, tr.GetExternalAddr(&net.UDPAddr{}))

	err = tr.RegisterIntroducer(&ssu2noise.RegisteredIntroducer{})
	assert.ErrorIs(t, err, ErrTransportNotStarted)

	assert.Nil(t, tr.GetIntroducers())

	_, err = tr.AllocateRelayTag(&net.UDPAddr{})
	assert.ErrorIs(t, err, ErrTransportNotStarted)
}
