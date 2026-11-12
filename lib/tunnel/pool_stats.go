package tunnel

import "sync/atomic"

// BuildStats is a point-in-time snapshot of the tunnel-build counters a Pool
// keeps. Issue #55 was diagnosable only from a 290 MB debug log because nothing
// here existed: a user could see tunnels never became ready but could not tell
// whether builds were never attempted, attempted against undialable gateways,
// or attempted and refused.
//
// The style matches transport.MuxSessionFailureStats: plain uint64 fields
// incremented atomically on the hot path, exposed as a snapshot. Counters are
// monotonic for the life of the pool; they are never reset, so a dashboard can
// diff them.
type BuildStats struct {
	// BuildsAttempted counts every BuildTunnel call the pool made, successful
	// or not, including retries.
	BuildsAttempted uint64

	// BuildsNoDialableCandidate counts attempts that failed before reaching any
	// peer -- we had no writable session to the selected gateway and could not
	// establish one. This is the counter that was nonzero throughout issue #55.
	BuildsNoDialableCandidate uint64

	// BuildsRefused counts attempts whose build request reached the gateway and
	// failed downstream. Unlike the counter above, this one says something about
	// the peers we picked.
	BuildsRefused uint64

	// PeersPenalizedGatewayUnreachable counts peers penalized for a failure to
	// dial them. Kept separate from the refusal count because the two deserve
	// different penalties (issue #55 requirement 2).
	PeersPenalizedGatewayUnreachable uint64

	// PeersPenalizedRefused counts peers penalized because a build that reached
	// them failed downstream.
	PeersPenalizedRefused uint64

	// PeersPenalizedUnknown counts peers penalized for a failure that could not
	// be attributed to either mode, e.g. a build timeout with no reply.
	PeersPenalizedUnknown uint64
}

// buildCounters is the mutable side of [BuildStats], held by the pool. Fields
// are accessed only through atomic operations, so they need no lock and cannot
// race the maintenance goroutine with a reader calling [Pool.GetBuildStats].
type buildCounters struct {
	attempted        atomic.Uint64
	noDialable       atomic.Uint64
	refused          atomic.Uint64
	penalizedUnreach atomic.Uint64
	penalizedRefused atomic.Uint64
	penalizedUnknown atomic.Uint64
}

func (c *buildCounters) snapshot() BuildStats {
	return BuildStats{
		BuildsAttempted:                  c.attempted.Load(),
		BuildsNoDialableCandidate:        c.noDialable.Load(),
		BuildsRefused:                    c.refused.Load(),
		PeersPenalizedGatewayUnreachable: c.penalizedUnreach.Load(),
		PeersPenalizedRefused:            c.penalizedRefused.Load(),
		PeersPenalizedUnknown:            c.penalizedUnknown.Load(),
	}
}

// GetBuildStats returns a snapshot of this pool's build counters. Safe to call
// concurrently with pool maintenance.
func (p *Pool) GetBuildStats() BuildStats {
	return p.counters.snapshot()
}

func (p *Pool) recordBuildAttempt() { p.counters.attempted.Add(1) }

func (p *Pool) recordBuildNoDialableCandidate() { p.counters.noDialable.Add(1) }

func (p *Pool) recordBuildRefused() { p.counters.refused.Add(1) }

// recordPeerPenalized increments the by-cause counter matching a failure
// reason, so "how many peers did we blame, and for what" is answerable without
// a debug log.
func (p *Pool) recordPeerPenalized(reason string) {
	switch reason {
	case "tunnel_build_failed_gateway_unreachable":
		p.counters.penalizedUnreach.Add(1)
	case "tunnel_build_failed_refused", "tunnel_build_failed_permanent":
		p.counters.penalizedRefused.Add(1)
	default:
		p.counters.penalizedUnknown.Add(1)
	}
}
