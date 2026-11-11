// Honest multi-layer encapsulation tests.
//
// These exercise the property the tunnel creator actually needs: an N-hop
// outbound tunnel requires all N layers applied by the creator, because every
// transit hop removes exactly one layer and forwards the rest. A single-layer
// gateway produces a record hop 0 can peel but that the remaining hops (and so
// the endpoint) can never decrypt.
//
// Unlike the participant round-trip test, which re-pads the buffer to 1008
// bytes between layers and so never proves real chaining, these tests feed each
// layer's full 1028-byte output into the next layer, then peel with the real
// per-hop keys in path order and assert the endpoint recovers the original
// record — same IV, valid checksum, intact delivery instructions and payload.

package tunnel

import (
	"crypto/rand"
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeHopLayers builds n independent AES layer encryptors plus their keys,
// returned in tunnel PATH order: index 0 is the gateway (hop 0, outermost
// layer) and the last index is the endpoint (innermost layer).
func makeHopLayers(t *testing.T, n int) ([]tunnel.TunnelEncryptor, []tunnel.TunnelKey, []tunnel.TunnelKey) {
	t.Helper()
	require.Greater(t, n, 0)

	layerKeys := make([]tunnel.TunnelKey, n)
	ivKeys := make([]tunnel.TunnelKey, n)
	layers := make([]tunnel.TunnelEncryptor, n)

	for i := 0; i < n; i++ {
		var lk, ik tunnel.TunnelKey
		_, err := rand.Read(lk[:])
		require.NoError(t, err)
		_, err = rand.Read(ik[:])
		require.NoError(t, err)

		enc, err := tunnel.NewAESEncryptor(lk, ik)
		require.NoError(t, err)

		layerKeys[i] = lk
		ivKeys[i] = ik
		layers[i] = enc
	}
	return layers, layerKeys, ivKeys
}

// TestGateway_MultiLayerRoundTrip peels a creator-layered record with the real
// per-hop keys in path order and asserts the endpoint recovers the original.
func TestGateway_MultiLayerRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		hopCnt  int
		msgSize int
	}{
		{name: "1-hop", hopCnt: 1, msgSize: 100},
		{name: "2-hop", hopCnt: 2, msgSize: 100},
		{name: "3-hop (default tunnel length)", hopCnt: 3, msgSize: 100},
		{name: "4-hop large message", hopCnt: 4, msgSize: 600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layers, layerKeys, ivKeys := makeHopLayers(t, tt.hopCnt)

			var gatewayHash [HashSize]byte
			_, err := rand.Read(gatewayHash[:])
			require.NoError(t, err)

			gw, err := NewGatewayWithLayers(TunnelID(5000), layers, TunnelID(6000))
			require.NoError(t, err)
			require.Equal(t, tt.hopCnt, gw.HopCount())

			msg := make([]byte, tt.msgSize)
			_, err = rand.Read(msg)
			require.NoError(t, err)

			records, err := gw.SendWithDelivery(msg, TunnelDelivery(7000, gatewayHash))
			require.NoError(t, err)
			require.Len(t, records, 1, "message fits in one tunnel message")
			require.Len(t, records[0], TunnelMessageSize)

			// The wire record must carry the gateway's (hop 0) receive tunnel
			// ID in the clear so hop 0 can route it.
			assert.Equal(t, uint32(6000), readTunnelIDFromRecord(records[0]),
				"wire record must be addressed to hop 0's receive tunnel ID")

			// Peel one layer per hop, in path order: hop 0 first.
			current := records[0]
			for hop := 0; hop < tt.hopCnt; hop++ {
				enc, err := tunnel.NewAESEncryptor(layerKeys[hop], ivKeys[hop])
				require.NoError(t, err)

				current, err = enc.Decrypt(current)
				require.NoError(t, err, "hop %d must be able to peel its layer", hop)
				require.Len(t, current, TunnelMessageSize)
			}

			// After the last layer is removed the record is back in the
			// creator's plaintext view: the original IV must be restored,
			// otherwise the endpoint's checksum cannot verify.
			assertValidChecksum(t, current)

			payload, di := extractPayloadFromRecord(t, current)
			assert.Equal(t, msg, payload, "endpoint must recover the original message bytes")
			assert.Equal(t, byte(DTTunnel), di.deliveryType, "delivery type must survive layering")
			assert.Equal(t, uint32(7000), di.tunnelID, "destination tunnel ID must survive layering")
			assert.Equal(t, common.Hash(gatewayHash), di.hash, "gateway hash must survive layering")
		})
	}
}

// TestGateway_SingleLayerIsNotMultiHopCapable pins the defect that made the
// gateway path unusable for real tunnels: a one-layer gateway produces a record
// that hop 0 can peel but that the endpoint of a 3-hop tunnel cannot.
func TestGateway_SingleLayerIsNotMultiHopCapable(t *testing.T) {
	layers, layerKeys, ivKeys := makeHopLayers(t, 3)

	var gatewayHash [HashSize]byte
	_, err := rand.Read(gatewayHash[:])
	require.NoError(t, err)

	msg := make([]byte, 100)
	_, err = rand.Read(msg)
	require.NoError(t, err)

	// Legacy single-layer construction.
	gw, err := NewGateway(TunnelID(1), layers[0], TunnelID(6000))
	require.NoError(t, err)
	require.Equal(t, 1, gw.HopCount())

	records, err := gw.SendWithDelivery(msg, TunnelDelivery(7000, gatewayHash))
	require.NoError(t, err)

	// Hop 0 peels fine...
	hop0, err := tunnel.NewAESEncryptor(layerKeys[0], ivKeys[0])
	require.NoError(t, err)
	afterHop0, err := hop0.Decrypt(records[0])
	require.NoError(t, err)

	// ...but the record is not the endpoint's, so the tunnel is not actually
	// established end to end: peeling hops 1 and 2 with their own keys yields
	// garbage the endpoint cannot use.
	mid, err := tunnel.NewAESEncryptor(layerKeys[1], ivKeys[1])
	require.NoError(t, err)
	partial, err := mid.Decrypt(afterHop0)
	require.NoError(t, err)

	endpoint, err := tunnel.NewAESEncryptor(layerKeys[2], ivKeys[2])
	require.NoError(t, err)
	final, err := endpoint.Decrypt(partial)
	require.NoError(t, err)

	// The checksum over the recovered bytes must NOT validate: proof that a
	// single-layer gateway cannot carry a multi-hop tunnel.
	assert.NotEqual(t, checksumOf(final), readChecksumFromRecord(final),
		"single-layer record must not validate at a 3-hop endpoint")
}

// TestGateway_LayeredPeelMatchesParticipantProcess verifies the layers the
// creator applies are removable by the same Participant/Endpoint code the
// router uses to relay, so this is not a test-only fiction.
func TestGateway_LayeredPeelMatchesParticipantProcess(t *testing.T) {
	const hops = 3

	layers, _, _ := makeHopLayers(t, hops)

	var gatewayHash [HashSize]byte
	_, err := rand.Read(gatewayHash[:])
	require.NoError(t, err)

	gw, err := NewGatewayWithLayers(TunnelID(5000), layers, TunnelID(6000))
	require.NoError(t, err)

	msg := make([]byte, 120)
	_, err = rand.Read(msg)
	require.NoError(t, err)

	records, err := gw.SendWithDelivery(msg, TunnelDelivery(7000, gatewayHash))
	require.NoError(t, err)

	// Transit hops 0..hops-2 relay via Participant.Process.
	current := records[0]
	for hop := 0; hop < hops-1; hop++ {
		p, err := NewParticipant(TunnelID(6000+hop), layers[hop])
		require.NoError(t, err)
		_, decrypted, err := p.Process(current)
		require.NoError(t, err, "participant hop %d must peel its layer", hop)
		current = decrypted
	}

	// The endpoint terminates the tunnel. Because the delivery instruction is
	// DTTunnel, the endpoint hands the message to its MessageForwarder rather
	// than the local handler — the same path production uses to reach the
	// destination's gateway.
	fwd := &captureForwarder{}
	endpoint, err := NewEndpoint(TunnelID(6000+hops-1), layers[hops-1], func(b []byte) error {
		t.Error("local handler must not be invoked for DTTunnel delivery")
		return nil
	})
	require.NoError(t, err)
	endpoint.SetForwarder(fwd)
	defer endpoint.Stop()

	require.NoError(t, endpoint.Receive(current))

	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	require.Len(t, fwd.tunnelForwards, 1, "endpoint must forward the DTTunnel message")
	assert.Equal(t, msg, fwd.tunnelForwards[0].payload,
		"forwarded payload must equal the original message bytes")
	assert.Equal(t, uint32(7000), fwd.tunnelForwards[0].tunnelID,
		"forwarded destination tunnel ID must survive layering")
	assert.Equal(t, gatewayHash[:], fwd.tunnelForwards[0].hash,
		"forwarded gateway hash must survive layering")
}

// captureForwarder records what the endpoint asks the router to forward.
type captureForwarder struct {
	mu             sync.Mutex
	tunnelForwards []forwardRecord
	routerForwards []forwardRecord
}

type forwardRecord struct {
	tunnelID uint32
	hash     []byte
	payload  []byte
}

func (f *captureForwarder) ForwardToTunnel(tunnelID uint32, hash [HashSize]byte, msg []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(msg))
	copy(cp, msg)
	f.tunnelForwards = append(f.tunnelForwards, forwardRecord{tunnelID: tunnelID, hash: hash[:], payload: cp})
	return nil
}

func (f *captureForwarder) ForwardToRouter(hash [HashSize]byte, msg []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(msg))
	copy(cp, msg)
	f.routerForwards = append(f.routerForwards, forwardRecord{hash: hash[:], payload: cp})
	return nil
}

// TestNewGatewayWithLayersValidation covers the constructor's guards.
func TestNewGatewayWithLayersValidation(t *testing.T) {
	enc, err := tunnel.NewAESEncryptor(tunnel.TunnelKey{1}, tunnel.TunnelKey{2})
	require.NoError(t, err)

	t.Run("empty layers rejected", func(t *testing.T) {
		_, err := NewGatewayWithLayers(TunnelID(1), nil, TunnelID(2))
		require.ErrorIs(t, err, ErrNilEncryption)

		_, err = NewGatewayWithLayers(TunnelID(1), []tunnel.TunnelEncryptor{}, TunnelID(2))
		require.ErrorIs(t, err, ErrNilEncryption)
	})

	t.Run("nil layer rejected", func(t *testing.T) {
		_, err := NewGatewayWithLayers(TunnelID(1),
			[]tunnel.TunnelEncryptor{enc, nil}, TunnelID(2))
		require.ErrorIs(t, err, ErrNilEncryption)
	})

	t.Run("caller slice mutation does not affect gateway", func(t *testing.T) {
		layers := []tunnel.TunnelEncryptor{enc, enc}
		gw, err := NewGatewayWithLayers(TunnelID(1), layers, TunnelID(2))
		require.NoError(t, err)

		layers[0] = nil // must not be visible through the gateway
		_, err = gw.Send([]byte("hello"))
		require.NoError(t, err)
	})
}

// ──────────────────────────────────────────────────────────────────────────────
// record inspection helpers (test-only)
// ──────────────────────────────────────────────────────────────────────────────

func readTunnelIDFromRecord(rec []byte) uint32 {
	return uint32(rec[TunnelIDOffset])<<24 |
		uint32(rec[TunnelIDOffset+1])<<16 |
		uint32(rec[TunnelIDOffset+2])<<8 |
		uint32(rec[TunnelIDOffset+3])
}

func readChecksumFromRecord(rec []byte) []byte {
	out := make([]byte, TunnelChecksumSize)
	copy(out, rec[TunnelChecksumOffset:TunnelHeaderSize])
	return out
}

// checksumOf recomputes the spec checksum: first 4 bytes of
// SHA256(bytes after the zero separator + IV).
func checksumOf(rec []byte) []byte {
	iv := rec[TunnelIVOffset:TunnelChecksumOffset]
	dataStart, err := findZeroSeparator(rec)
	if err != nil {
		return nil
	}
	buf := make([]byte, 0, len(rec)-dataStart+len(iv))
	buf = append(buf, rec[dataStart:]...)
	buf = append(buf, iv...)
	sum := types.SHA256(buf)
	return sum[:TunnelChecksumSize]
}

func assertValidChecksum(t *testing.T, rec []byte) {
	t.Helper()
	require.Len(t, rec, TunnelMessageSize)
	expected := checksumOf(rec)
	require.NotNil(t, expected, "record must contain a zero separator")
	assert.Equal(t, expected, readChecksumFromRecord(rec),
		"endpoint checksum verification must pass over the restored IV")
}

func extractPayloadFromRecord(t *testing.T, rec []byte) ([]byte, *DeliveryInstructions) {
	t.Helper()
	dataStart, err := findZeroSeparator(rec)
	require.NoError(t, err)

	di, remainder, err := readDeliveryInstructions(rec[dataStart:])
	require.NoError(t, err)

	fragSize, err := di.FragmentSize()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(remainder), int(fragSize), "record must carry the fragment")

	return remainder[:fragSize], di
}
