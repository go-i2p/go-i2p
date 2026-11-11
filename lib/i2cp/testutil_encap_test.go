// Shared test helpers for outbound tunnel encapsulation.
//
// Outbound sends now require two things the old bare-send tests never provided:
// a tunnel whose build retained per-hop layer keys, and a destination lease to
// address the tunnel message to. These helpers produce both so tests can drive
// the real encapsulation path instead of stubbing it out.

package i2cp

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	cryptoTunnel "github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/require"
)

// addRetainedLayers gives a tunnel state the per-hop layer keys and IDs a real
// build would have retained, so CreatorGateway() succeeds.
//
// Keys are random, exactly as in production. The receive IDs are assigned
// sequentially from baseReceive so tests can assert on the in-clear record ID
// without parsing keys.
func addRetainedLayers(t *testing.T, state *tunnel.TunnelState, baseReceive tunnel.TunnelID) {
	t.Helper()
	require.NotEmpty(t, state.Hops, "a tunnel with no hops cannot retain layers")

	hopCnt := len(state.Hops)
	layers := make([]tunnel.TunnelLayer, hopCnt)
	for i := 0; i < hopCnt; i++ {
		var lk, ivk [32]byte
		_, err := rand.Read(lk[:])
		require.NoError(t, err)
		_, err = rand.Read(ivk[:])
		require.NoError(t, err)

		receive := baseReceive + tunnel.TunnelID(i)
		next := baseReceive + tunnel.TunnelID(i+1)
		if i == hopCnt-1 {
			next = receive // endpoint hop: no further hop in this tunnel
		}
		layers[i] = tunnel.TunnelLayer{
			LayerKey:      lk,
			IVKey:         ivk,
			ReceiveTunnel: receive,
			NextTunnel:    next,
		}
	}
	state.SetLayers(layers)
}

// fakeLeaseResolver is a DestinationLeaseResolver with canned answers, so tests
// do not need a NetDB to exercise the addressing path.
type fakeLeaseResolver struct {
	targets map[common.Hash]LeaseTarget
	err     error
	calls   []common.Hash
}

func newFakeLeaseResolver() *fakeLeaseResolver {
	return &fakeLeaseResolver{targets: make(map[common.Hash]LeaseTarget)}
}

func (f *fakeLeaseResolver) add(dest common.Hash, gateway common.Hash, tunnelID uint32) {
	f.targets[dest] = LeaseTarget{
		GatewayHash: gateway,
		TunnelID:    tunnelID,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
}

func (f *fakeLeaseResolver) fail(err error) { f.err = err }

func (f *fakeLeaseResolver) ResolveLease(destHash common.Hash) (LeaseTarget, error) {
	f.calls = append(f.calls, destHash)
	if f.err != nil {
		return LeaseTarget{}, f.err
	}
	target, ok := f.targets[destHash]
	if !ok {
		return LeaseTarget{}, ErrNoLease
	}
	return target, nil
}

// sentRecord is one TunnelData message captured from the transport, parsed into
// the fields a test needs to assert on.
type sentRecord struct {
	hop      common.Hash // peer the transport was asked to send to
	headerID uint32      // TunnelData header ID: the reader's tunnel ID
	record   []byte      // full 1028-byte record (header ID + 1024-byte payload)
}

// captureTransport returns a TransportSendFunc that records the tunnel records
// it is handed. A non-TunnelData message is a test failure: after I2P-002 the
// outbound path must only ever emit TunnelData to a hop.
func captureTransport(t *testing.T) (TransportSendFunc, *[]sentRecord) {
	t.Helper()

	records := make([]sentRecord, 0, 4)
	send := func(peer common.Hash, msg i2np.Message) error {
		carrier, ok := msg.(i2np.TunnelCarrier)
		if !ok {
			t.Errorf("outbound path sent %T (I2NP type %d) to a hop; expected TunnelData",
				msg, msg.Type())
			return nil
		}

		data := carrier.GetTunnelData()
		require.Len(t, data, i2np.TunnelDataPayloadSize, "TunnelData payload must be 1024 bytes")

		// Reassemble the 1028-byte record the gateway produced: the header
		// carries the reader's ID and the body repeats it in the clear.
		full := make([]byte, tunnel.TunnelMessageSize)
		binary.BigEndian.PutUint32(full[:tunnel.TunnelIDSize], uint32(carrier.GetTunnelID()))
		copy(full[tunnel.TunnelIDSize:], data)

		records = append(records, sentRecord{
			hop:      peer,
			headerID: uint32(carrier.GetTunnelID()),
			record:   full,
		})
		return nil
	}
	return send, &records
}

// recordPlaintext peels every hop layer of a captured record, in path order,
// using the hop keys the test installed with addRetainedLayers. It returns the
// creator's plaintext view of the record plus the delivery instructions the
// endpoint would read from it.
func recordPlaintext(t *testing.T, state *tunnel.TunnelState, record []byte) ([]byte, *tunnel.DeliveryInstructions) {
	t.Helper()

	layers := state.GetLayers()
	require.NotEmpty(t, layers, "tunnel must retain layers to peel")

	current := record
	for i := range layers {
		enc, err := cryptoTunnel.NewAESEncryptor(asTunnelKey(layers[i].LayerKey), asTunnelKey(layers[i].IVKey))
		require.NoError(t, err)
		current, err = enc.Decrypt(current)
		require.NoError(t, err, "hop %d must peel its layer", i)
	}

	dataStart := indexZeroSeparator(t, current)
	di, err := tunnel.NewDeliveryInstructions(current[dataStart:])
	require.NoError(t, err)
	return current, di
}

// recordPayload returns the fragment the endpoint would deliver to its client.
func recordPayload(t *testing.T, record []byte, di *tunnel.DeliveryInstructions) []byte {
	t.Helper()

	dataStart := indexZeroSeparator(t, record)
	diLen, err := diLength(di)
	require.NoError(t, err)

	fragSize, err := di.FragmentSize()
	require.NoError(t, err)

	start := dataStart + diLen
	require.GreaterOrEqual(t, len(record), start+int(fragSize), "record must carry the fragment")
	return record[start : start+int(fragSize)]
}

// diLength reports how many bytes a set of delivery instructions occupies on
// the wire, using its own serializer so the measurement matches the encoder.
func diLength(di *tunnel.DeliveryInstructions) (int, error) {
	b, err := di.Bytes()
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func asTunnelKey(b [32]byte) cryptoTunnel.TunnelKey {
	var k cryptoTunnel.TunnelKey
	copy(k[:], b[:])
	return k
}

func indexZeroSeparator(t *testing.T, rec []byte) int {
	t.Helper()
	for i := tunnel.TunnelHeaderSize; i < len(rec); i++ {
		if rec[i] == tunnel.TunnelZeroSeparator {
			return i + 1
		}
	}
	t.Fatal("record has no zero separator")
	return 0
}
