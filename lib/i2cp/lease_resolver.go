// Destination lease resolution for outbound I2CP messages.
//
// To address a tunnel message to a remote destination the sender needs the
// destination's inbound tunnel: the gateway router's identity hash and the
// tunnel ID at that gateway, both taken from a current lease in the
// destination's LeaseSet. This is the piece that was missing from the outbound
// path — without it a message cannot be addressed to anybody, and the previous
// behaviour was to skip addressing entirely and hand the bare garlic message to
// the transport.
//
// Resolution is deliberately fail-closed: an absent, unparseable, or fully
// expired LeaseSet is an error, and the caller must drop the message rather
// than fall back to sending it unprotected.

package i2cp

import (
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// LeaseTarget is the inbound-tunnel addressing a sender extracts from a
// destination's lease.
type LeaseTarget struct {
	// GatewayHash is the identity hash of the destination's inbound tunnel
	// gateway (IBGW). It is a ROUTER hash, so it is the peer the first hop of
	// our outbound tunnel must ultimately reach.
	GatewayHash common.Hash

	// TunnelID is the gateway receive tunnel ID for the destination's inbound
	// tunnel. It goes in the DTTunnel delivery instructions of the tunnel
	// message we originate.
	TunnelID uint32

	// ExpiresAt is when the selected lease expires.
	ExpiresAt time.Time
}

// IsZero reports whether the target carries no addressing.
func (lt LeaseTarget) IsZero() bool {
	return lt.GatewayHash == (common.Hash{}) && lt.TunnelID == 0
}

// LeaseSetFetcher is the NetDB surface needed to resolve leases. Both
// lease-set generations are fetched separately because the two are stored in
// distinct buckets and a destination publishes only one of them.
type LeaseSetFetcher interface {
	GetLeaseSetBytes(hash common.Hash) ([]byte, error)
	GetLeaseSet2Bytes(hash common.Hash) ([]byte, error)
}

// LeaseResolver resolves a destination hash to its current inbound tunnel
// lease. It satisfies DestinationLeaseResolver.
type LeaseResolver struct {
	fetcher LeaseSetFetcher
	// now is injectable so lease-expiry selection can be tested without
	// sleeping.
	now func() time.Time
}

// NewLeaseResolver creates a resolver backed by the given NetDB accessor.
// A nil fetcher yields a resolver that always reports unresolvable, which keeps
// the send path fail-closed rather than silently unaddressed.
func NewLeaseResolver(fetcher LeaseSetFetcher) *LeaseResolver {
	return &LeaseResolver{fetcher: fetcher, now: time.Now}
}

// ResolveLease looks up destHash's LeaseSet and selects a live lease.
//
// LeaseSet2 is tried first since it is the modern default (I2P 0.9.38+), then
// the classic v1 LeaseSet. Within a set the lease with the latest expiration is
// chosen, matching the heuristic used by the garlic router.
func (r *LeaseResolver) ResolveLease(destHash common.Hash) (LeaseTarget, error) {
	if r == nil || r.fetcher == nil {
		return LeaseTarget{}, oops.With("destination", logutil.HashPrefixPlain(destHash)).
			Errorf("no NetDB accessor configured to resolve destination lease")
	}

	if target, err := r.resolveLeaseSet2(destHash); err == nil {
		return target, nil
	}
	if target, err := r.resolveLeaseSet1(destHash); err == nil {
		return target, nil
	}

	return LeaseTarget{}, oops.With("destination", logutil.HashPrefixPlain(destHash)).
		Wrapf(ErrNoLease, "destination has no usable lease in LeaseSet2 or LeaseSet")
}

// resolveLeaseSet2 reads a LeaseSet2 and selects a live lease from it.
func (r *LeaseResolver) resolveLeaseSet2(destHash common.Hash) (LeaseTarget, error) {
	data, err := r.fetcher.GetLeaseSet2Bytes(destHash)
	if err != nil || len(data) == 0 {
		return LeaseTarget{}, errNoLeaseSet2
	}

	ls2, _, err := lease_set2.ReadLeaseSet2(data)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.LeaseResolver.resolveLeaseSet2",
			"destination": logutil.HashPrefixPlain(destHash),
			"error":       err.Error(),
		}).Debug("failed to parse LeaseSet2")
		return LeaseTarget{}, errNoLeaseSet2
	}
	if !ls2.IsValid() {
		return LeaseTarget{}, errNoLeaseSet2
	}

	return r.selectFromLeases2(ls2.Leases(), destHash)
}

// resolveLeaseSet1 reads a classic LeaseSet and selects a live lease from it.
func (r *LeaseResolver) resolveLeaseSet1(destHash common.Hash) (LeaseTarget, error) {
	data, err := r.fetcher.GetLeaseSetBytes(destHash)
	if err != nil || len(data) == 0 {
		return LeaseTarget{}, errNoLeaseSet1
	}

	ls, err := lease_set.ReadLeaseSet(data)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.LeaseResolver.resolveLeaseSet1",
			"destination": logutil.HashPrefixPlain(destHash),
			"error":       err.Error(),
		}).Debug("failed to parse LeaseSet")
		return LeaseTarget{}, errNoLeaseSet1
	}
	if !ls.IsValid() {
		return LeaseTarget{}, errNoLeaseSet1
	}

	return r.selectFromLeases1(ls.Leases(), destHash)
}

// selectFromLeases2 picks the non-expired Lease2 with the latest expiration.
func (r *LeaseResolver) selectFromLeases2(leases []lease.Lease2, destHash common.Hash) (LeaseTarget, error) {
	now := r.currentTime()
	var best *lease.Lease2

	for i := range leases {
		l := leases[i]
		if l.IsExpired() {
			continue
		}
		end := time.Unix(int64(l.EndDate()), 0)
		if end.Before(now) {
			continue
		}
		if best == nil || end.After(time.Unix(int64(best.EndDate()), 0)) {
			best = &l
		}
	}

	if best == nil {
		return LeaseTarget{}, errNoLiveLease
	}
	target := LeaseTarget{
		GatewayHash: common.Hash(best.TunnelGateway()),
		TunnelID:    best.TunnelID(),
		ExpiresAt:   time.Unix(int64(best.EndDate()), 0),
	}
	logLeaseSelected("LeaseSet2", destHash, target)
	return target, nil
}

// selectFromLeases1 picks the non-expired v1 Lease with the latest expiration.
func (r *LeaseResolver) selectFromLeases1(leases []lease.Lease, destHash common.Hash) (LeaseTarget, error) {
	now := r.currentTime()
	var best *lease.Lease

	for i := range leases {
		l := leases[i]
		if l.IsExpired() {
			continue
		}
		exp := l.Time()
		if exp.Before(now) {
			continue
		}
		if best == nil || exp.After(best.Time()) {
			best = &l
		}
	}

	if best == nil {
		return LeaseTarget{}, errNoLiveLease
	}
	target := LeaseTarget{
		GatewayHash: common.Hash(best.TunnelGateway()),
		TunnelID:    best.TunnelID(),
		ExpiresAt:   best.Time(),
	}
	logLeaseSelected("LeaseSet", destHash, target)
	return target, nil
}

func (r *LeaseResolver) currentTime() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

func logLeaseSelected(kind string, destHash common.Hash, target LeaseTarget) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.LeaseResolver.ResolveLease",
		"leaseset":    kind,
		"destination": logutil.HashPrefixPlain(destHash),
		"gateway":     logutil.HashPrefixPlain(target.GatewayHash),
		"tunnel_id":   target.TunnelID,
	}).Debug("selected destination lease for outbound tunnel addressing")
}
