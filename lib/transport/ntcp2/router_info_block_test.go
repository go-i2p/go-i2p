package ntcp2

import (
	"bytes"
	"compress/gzip"
	"context"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// routerInfoBlockPayload builds the data-phase RouterInfo block payload: 1 flag
// byte followed by the serialized RouterInfo, exactly as ntcp2.rst specifies.
func routerInfoBlockPayload(t *testing.T, riBytes []byte, floodRequested bool) []byte {
	t.Helper()
	flag := byte(0)
	if floodRequested {
		flag = 1
	}
	out := make([]byte, 0, 1+len(riBytes))
	out = append(out, flag)
	out = append(out, riBytes...)
	return out
}

// TestHandleRouterInfoBlock_FlagBit0IsFloodRequestNotGzip guards the spec rule
// that bit 0 of a RouterInfo block means "flood request" and that RouterInfo is
// never gzip-compressed in NTCP2.
//
// The previous implementation treated flag&0x01 as a gzip indicator, so a peer
// setting the flood bit produced a "failed to decompress" drop.
func TestHandleRouterInfoBlock_FlagBit0IsFloodRequestNotGzip(t *testing.T) {
	ri := testutil.CreateSignedTestRouterInfo(t, nil, nil)
	riBytes, err := ri.Bytes()
	require.NoError(t, err)

	for _, flood := range []bool{false, true} {
		name := "local_store"
		if flood {
			name = "flood_request"
		}
		t.Run(name, func(t *testing.T) {
			var got []byte
			var gotFlood bool
			called := false

			session := NewNTCP2SessionDeferred(&mockConn{}, context.Background(), logger.WithField("test", t.Name()))
			session.SetRouterInfoCallback(func(b []byte, f bool) {
				called = true
				got = b
				gotFlood = f
			})

			session.handleRouterInfoBlock(routerInfoBlockPayload(t, riBytes, flood))

			require.True(t, called, "callback must run")
			assert.Equal(t, riBytes, got,
				"RouterInfo bytes must be passed through verbatim, never gunzipped")
			assert.Equal(t, flood, gotFlood,
				"flag bit 0 must be reported as the flood-request flag")
		})
	}
}

// TestHandleRouterInfoBlock_GzippedPayloadIsNotDecompressed proves the handler no
// longer attempts gzip decompression even when a payload happens to be gzip data.
func TestHandleRouterInfoBlock_GzippedPayloadIsNotDecompressed(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write([]byte("not-a-real-router-info"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	compressed := buf.Bytes()

	var got []byte
	session := NewNTCP2SessionDeferred(&mockConn{}, context.Background(), logger.WithField("test", t.Name()))
	session.SetRouterInfoCallback(func(b []byte, f bool) { got = b })

	// Flag bit 0 set: under the old buggy logic this was gunzipped and dropped.
	session.handleRouterInfoBlock(routerInfoBlockPayload(t, compressed, true))
	assert.Equal(t, compressed, got, "payload must not be transformed")
}

// --- transport-side handler tests ---

type routerInfoFloodCall struct {
	key      data.Hash
	data     []byte
	dataType byte
}

// routerInfoRecordingStorer captures RouterInfo storage calls.
type routerInfoRecordingStorer struct {
	stored []router_info.RouterInfo
}

func (f *routerInfoRecordingStorer) StoreRouterInfo(ri router_info.RouterInfo) {
	f.stored = append(f.stored, ri)
}

func (f *routerInfoRecordingStorer) StoreRouterInfoWithError(ri router_info.RouterInfo) error {
	f.stored = append(f.stored, ri)
	return nil
}

// routerInfoRecordingFlooder captures flood dispatches.
type routerInfoRecordingFlooder struct {
	calls []routerInfoFloodCall
}

func (f *routerInfoRecordingFlooder) FloodDatabaseStore(key data.Hash, payload []byte, dataType byte) {
	f.calls = append(f.calls, routerInfoFloodCall{key: key, data: payload, dataType: dataType})
}

// newRouterInfoTestTransport builds a minimal transport with the given storer and
// flooder wired, sufficient for handleDataPhaseRouterInfo.
func newRouterInfoTestTransport(storer *routerInfoRecordingStorer, flooder *routerInfoRecordingFlooder) *NTCP2Transport {
	tr := &NTCP2Transport{
		ctx:    context.Background(),
		logger: logger.WithField("test", "routerinfo-block"),
	}
	if storer != nil {
		tr.routerInfoStorer.Store(storer)
	}
	if flooder != nil {
		tr.routerInfoFlooder.Store(flooder)
	}
	return tr
}

func TestHandleDataPhaseRouterInfo_HashMismatchIsIgnored(t *testing.T) {
	ri := testutil.CreateSignedTestRouterInfo(t, nil, nil)
	riBytes, err := ri.Bytes()
	require.NoError(t, err)

	var otherHash data.Hash
	otherHash[0] = 0xAA

	storer := &routerInfoRecordingStorer{}
	flooder := &routerInfoRecordingFlooder{}
	tr := newRouterInfoTestTransport(storer, flooder)

	tr.handleDataPhaseRouterInfo("1.2.3.4:5", otherHash, riBytes, true)

	assert.Empty(t, storer.stored, "RouterInfo for a different peer must not be stored")
	assert.Empty(t, flooder.calls, "RouterInfo for a different peer must not be flooded")
}

func TestHandleDataPhaseRouterInfo_StoresWhenHashMatches(t *testing.T) {
	ri := testutil.CreateSignedTestRouterInfo(t, nil, nil)
	riBytes, err := ri.Bytes()
	require.NoError(t, err)
	peerHash, err := ri.IdentHash()
	require.NoError(t, err)

	storer := &routerInfoRecordingStorer{}
	flooder := &routerInfoRecordingFlooder{}
	tr := newRouterInfoTestTransport(storer, flooder)

	tr.handleDataPhaseRouterInfo("1.2.3.4:5", peerHash, riBytes, false)

	assert.Len(t, storer.stored, 1, "matching RouterInfo must be stored locally")
	assert.Empty(t, flooder.calls, "must not flood when flag bit 0 is clear")
}

func TestHandleDataPhaseRouterInfo_FloodsWhenRequested(t *testing.T) {
	ri := testutil.CreateSignedTestRouterInfo(t, nil, nil)
	riBytes, err := ri.Bytes()
	require.NoError(t, err)
	peerHash, err := ri.IdentHash()
	require.NoError(t, err)

	storer := &routerInfoRecordingStorer{}
	flooder := &routerInfoRecordingFlooder{}
	tr := newRouterInfoTestTransport(storer, flooder)

	tr.handleDataPhaseRouterInfo("1.2.3.4:5", peerHash, riBytes, true)

	require.Len(t, flooder.calls, 1, "flag bit 0 must trigger flooding")
	assert.Equal(t, peerHash, flooder.calls[0].key)
	assert.Equal(t, riBytes, flooder.calls[0].data,
		"the original wire bytes must be flooded, not a re-serialization")
	assert.Equal(t, byte(i2np.DatabaseStoreTypeRouterInfo), flooder.calls[0].dataType)
}

func TestHandleDataPhaseRouterInfo_MalformedBytesIgnored(t *testing.T) {
	var peerHash data.Hash
	storer := &routerInfoRecordingStorer{}
	tr := newRouterInfoTestTransport(storer, nil)

	tr.handleDataPhaseRouterInfo("1.2.3.4:5", peerHash, []byte("garbage"), false)
	assert.Empty(t, storer.stored, "malformed RouterInfo must not be stored")
}

func TestHandleDataPhaseRouterInfo_NoStorerIsNoop(t *testing.T) {
	ri := testutil.CreateSignedTestRouterInfo(t, nil, nil)
	riBytes, err := ri.Bytes()
	require.NoError(t, err)
	peerHash, err := ri.IdentHash()
	require.NoError(t, err)

	flooder := &routerInfoRecordingFlooder{}
	tr := newRouterInfoTestTransport(nil, flooder)

	// Must not panic when no storer is configured.
	tr.handleDataPhaseRouterInfo("1.2.3.4:5", peerHash, riBytes, true)
	assert.Empty(t, flooder.calls, "nothing to flood when the RouterInfo was never stored")
}
