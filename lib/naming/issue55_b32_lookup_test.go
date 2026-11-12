// Issue #55, smaller item: NAMING LOOKUP for a .b32.i2p address returned
// KEY_NOT_FOUND in 0.0 s with no netDb lookup attempted.
//
// Cause: I2CP's handleHostnameLookup calls ResolveHostname, which was a pure
// hosts.txt map lookup. A b32 address is derived from a destination hash and is
// never a hosts.txt entry, so the map always missed and returned immediately --
// the 0.0 s the reporter saw. The NetDB-aware path lived in Resolve, which
// nothing in lib/i2cp called, and SetNetDB was never called from
// configureI2CPHostnameResolver either.
//
// These tests pin both halves: ResolveHostname must dispatch a b32 address to
// the NetDB path, and the lookup must genuinely be attempted.

package naming

import (
	"strings"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lookupRecordingNetDB records whether GetLeaseSet was called and returns a
// closed channel, which the resolver treats as "not found". A closed channel
// keeps the mock free of any real LeaseSet construction -- the point under test
// is that a lookup is attempted at all, not what it returns.
type lookupRecordingNetDB struct {
	calledWith []common.Hash
	closed     bool
}

func (m *lookupRecordingNetDB) GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet {
	m.calledWith = append(m.calledWith, hash)
	ch := make(chan lease_set.LeaseSet)
	if m.closed {
		close(ch)
	}
	return ch
}

// TestIssue55_ResolveHostname_AttemptsNetDBLookupForB32 is the core guard: a b32
// address must reach the NetDB, not be answered from the hosts.txt map.
//
// Pre-fix this fails: ResolveHostname consulted only r.hosts, so calledWith
// stayed empty and the error was the map-miss "hostname not found".
func TestIssue55_ResolveHostname_AttemptsNetDBLookupForB32(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	netdb := &lookupRecordingNetDB{closed: true}
	r.SetNetDB(netdb)

	_, err = r.ResolveHostname("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p")

	require.Error(t, err, "a closed channel means not-found, which must still be an error")
	require.Len(t, netdb.calledWith, 1,
		"a netDb lookup must be attempted for a b32 address; the reported bug was "+
			"KEY_NOT_FOUND in 0.0s with no lookup attempted")

	// The hash queried must be the one the address encodes, proving the lookup
	// was for the right destination rather than a blind call.
	wantHash, err := ResolveB32Address("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p")
	require.NoError(t, err)
	var want common.Hash
	copy(want[:], wantHash)
	assert.Equal(t, want, netdb.calledWith[0], "the lookup must use the hash the b32 address encodes")
}

// TestIssue55_ResolveHostname_B32WithoutNetDBIsAnError pins the no-NetDB case:
// Resolve returns the 32-byte destination hash with isHash=true, and reporting
// that as a resolved destination would hand the caller a truncated record it
// cannot parse. An error keeps the reply an honest not-found.
func TestIssue55_ResolveHostname_B32WithoutNetDBIsAnError(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)
	require.False(t, r.HasNetDB(), "a fresh resolver has no NetDB")

	dest, err := r.ResolveHostname("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p")

	require.Error(t, err, "without a NetDB a b32 address cannot be resolved to a destination")
	assert.Nil(t, dest, "no destination may be returned alongside the error")
	assert.Contains(t, err.Error(), "requires a configured NetDB")
}

// TestIssue55_ResolveHostname_PlainHostnamesUnaffected guards the regression
// direction: dispatching b32 must not disturb ordinary hostname resolution.
func TestIssue55_ResolveHostname_PlainHostnamesUnaffected(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	netdb := &lookupRecordingNetDB{closed: true}
	r.SetNetDB(netdb)

	dest, err := r.ResolveHostname("zzz.i2p")
	require.NoError(t, err, "a hosts.txt hostname must still resolve")
	assert.NotEmpty(t, dest)
	assert.Empty(t, netdb.calledWith,
		"a plain hostname must not trigger a netDb LeaseSet lookup")

	_, err = r.ResolveHostname("definitely-not-registered.i2p")
	require.Error(t, err, "an unknown plain hostname must still be an error")
	assert.Empty(t, netdb.calledWith, "an unknown plain hostname must not hit the NetDB")
}

// TestIssue55_ResolveHostname_B32DispatchIsCaseAndSpaceTolerant pins that the
// b32 dispatch matches the same normalisation Resolve applies, so an
// uppercase-or-padded b32 query is not silently routed to the map.
func TestIssue55_ResolveHostname_B32DispatchIsCaseAndSpaceTolerant(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	netdb := &lookupRecordingNetDB{closed: true}
	r.SetNetDB(netdb)

	for _, variant := range []string{
		"ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p",
		"  ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p  ",
	} {
		netdb.calledWith = nil
		_, err := r.ResolveHostname(variant)
		require.Error(t, err)
		assert.Len(t, netdb.calledWith, 1,
			"variant %q must reach the NetDB, not the hosts.txt map", strings.TrimSpace(variant))
	}

	// Uppercase is dispatched to the b32 path rather than the map, but the
	// base32 alphabet is lowercase-only, so decoding still fails. Asserting the
	// error text distinguishes "dispatched and failed to decode" from the
	// pre-fix "hostname not found" map miss. This is pre-existing decode
	// behaviour, not something this change introduces or fixes.
	netdb.calledWith = nil
	_, err = r.ResolveHostname("UKEU3K5OYCGAAUNEQGTNVSELM4YEMVOILKLN7JPVAMVFX7DNKDQ.b32.i2p")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "hostname not found",
		"an uppercase b32 address must be dispatched to the b32 path, not answered from the map")
	assert.Empty(t, netdb.calledWith, "an undecodable address must not reach the NetDB")
}

// TestIssue55_ResolveHostname_B33IsNotResolvedByHashLookup pins that encrypted b33
// addresses keep their existing contract: they carry a public key rather than a
// hash, so the hash-keyed NetDB lookup does not apply and must not be attempted.
func TestIssue55_ResolveHostname_B33IsNotResolvedByHashLookup(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	netdb := &lookupRecordingNetDB{closed: true}
	r.SetNetDB(netdb)

	// 52-char b32 payload plus the suffix is a plain b32; a b33 address is
	// longer. Build one through the same helper the other tests use.
	addr := makeB33Address(t, make([]byte, 32), false, false)
	require.True(t, strings.HasSuffix(addr, B32Suffix))

	dest, err := r.ResolveHostname(addr)
	require.Error(t, err,
		"a b33 address carries a public key, not a Destination, so it cannot be "+
			"returned as one through the HostnameResolver contract")
	assert.Nil(t, dest, "no destination may be returned alongside the error")
	assert.Empty(t, netdb.calledWith,
		"a b33 address must not be sent to the hash-keyed NetDB lookup")
}

// TestIssue55_HasNetDBAccessor asserts the wiring guard exists so a dropped
// SetNetDB call fails a test instead of degrading silently.
func TestIssue55_HasNetDBAccessor(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	assert.False(t, r.HasNetDB())
	r.SetNetDB(&lookupRecordingNetDB{closed: true})
	assert.True(t, r.HasNetDB(), "the accessor must report a wired NetDB")
}

// TestIssue55_ResolveHostnameDoesNotDeadlockWithoutNetDB guards the locking
// change: ResolveHostname dispatches to Resolve before taking r.mu, because
// resolveB32 acquires r.mu itself. Re-acquiring a read lock while holding one
// can deadlock against an intervening writer, so exercise the path with a
// concurrent writer to make a regression fail rather than hang silently.
func TestIssue55_ResolveHostnameDoesNotDeadlockWithoutNetDB(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)
	r.SetNetDB(&lookupRecordingNetDB{closed: true})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			_, _ = r.ResolveHostname("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p")
		}
	}()

	// Concurrent writers on the same lock, so a wrongly-nested RLock has a
	// queued writer to deadlock against.
	for i := 0; i < 50; i++ {
		r.SetNetDB(&lookupRecordingNetDB{closed: true})
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ResolveHostname deadlocked on r.mu")
	}
}
