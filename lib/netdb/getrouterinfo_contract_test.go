// Contract tests for StdNetDB.GetRouterInfo: the lookup must return a
// definitive result — a channel that delivers the RouterInfo for a present
// hash, or a nil channel (not-found) for an absent one. It must never return a
// non-nil channel that closes empty, which callers previously mistook for a
// lookup that started but never delivered (the per-packet "failed to receive
// RouterInfo" transit-forwarding bug).

package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetRouterInfo_AbsentHashReturnsNilChannel asserts the definitive
// not-found contract: an absent hash yields a nil channel, never a non-nil
// channel that closes empty.
func TestGetRouterInfo_AbsentHashReturnsNilChannel(t *testing.T) {
	db := newTestStdNetDB(t)

	var absent common.Hash
	copy(absent[:], "absent-routerinfo-hash-0000000000")

	chnl := db.GetRouterInfo(absent)
	assert.Nil(t, chnl, "absent hash must yield a nil channel (definitive not-found)")
}

// TestGetRouterInfo_PresentHashDeliversValue asserts that a stored RouterInfo
// is delivered on a non-nil channel.
func TestGetRouterInfo_PresentHashDeliversValue(t *testing.T) {
	db := newTestStdNetDB(t)

	ri := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
	hash, err := ri.IdentHash()
	require.NoError(t, err)

	db.StoreRouterInfo(ri)

	chnl := db.GetRouterInfo(hash)
	require.NotNil(t, chnl, "present hash must yield a non-nil channel")

	got, ok := <-chnl
	require.True(t, ok, "present hash must deliver a RouterInfo, not close empty")
	gotHash, err := got.IdentHash()
	require.NoError(t, err)
	assert.Equal(t, hash, gotHash, "delivered RouterInfo must match the requested hash")
}

// TestGetRouterInfo_RefreshCooldownReturnsNilChannel pins the regression: after
// RequestRouterInfoRefresh evicts the cached entry, the on-disk copy is
// deliberately withheld for the cooldown window. The contract is a definitive
// not-found (nil channel) — NOT a non-nil channel that closes empty. A live
// peer whose RouterInfo was loaded at bootstrap and then refresh-requested must
// not produce the ambiguous empty close that caused per-packet forwarding
// errors.
func TestGetRouterInfo_RefreshCooldownReturnsNilChannel(t *testing.T) {
	db := newTestStdNetDB(t)

	ri := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
	hash, err := ri.IdentHash()
	require.NoError(t, err)

	db.StoreRouterInfo(ri)
	// Confirm it is present (cache hit path) before the refresh.
	chnl := db.GetRouterInfo(hash)
	require.NotNil(t, chnl)
	if _, ok := <-chnl; !ok {
		t.Fatal("expected RouterInfo before refresh")
	}

	// Evict from cache and start the refresh cooldown.
	db.RequestRouterInfoRefresh(hash)

	// During the cooldown the entry is withheld: definitive not-found (nil),
	// never a non-nil empty-closed channel.
	chnl = db.GetRouterInfo(hash)
	assert.Nil(t, chnl, "withheld RouterInfo during refresh cooldown must yield a nil channel, not an empty close")
}
