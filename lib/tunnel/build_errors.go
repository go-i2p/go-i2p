package tunnel

import (
	"errors"
	"strings"
)

// Build-outcome sentinels.
//
// Before these existed, every layer below the pool reported tunnel-build
// failures as prose and classified them by matching that prose. Two distinct
// failures collapsed into the same string, which is why issue #55 was
// undiagnosable: "we could not dial this peer" and "this peer refused the
// build" both surfaced as `no transports available`, and both drew the same
// penalty even though only the second says anything about the peer's
// suitability as a hop.
//
// lib/transport imports lib/tunnel, so lib/tunnel cannot import
// lib/transport and cannot name transport.ErrNoTransportAvailable directly.
// These sentinels are the other half of that seam: the router, which sees both
// packages, attaches the right one at the boundary with %w, and the pool then
// classifies with errors.Is.
//
// The prose classifiers remain as a fallback for builders that carry no
// sentinel (external builders, test doubles). A sentinel always wins when
// present, so classification stays deterministic.
var (
	// ErrGatewayUnreachable means the build request never reached the first
	// hop: we had no writable session to it and could not establish one. This
	// says something about our reachability to that address, not about the
	// peer's suitability as a hop, so it must not draw the same penalty as a
	// refusal. Only the gateway is implicated; the remaining hops were never
	// contacted.
	ErrGatewayUnreachable = errors.New("tunnel gateway unreachable")

	// ErrBuildRefused means the build request did reach the gateway and the
	// build failed downstream of it (a hop rejected it, or the reply reported
	// failure). The hop set is implicated, unlike a dial failure.
	ErrBuildRefused = errors.New("tunnel build refused")

	// ErrNoDialableCandidates is the terminal outcome of a retry loop in which
	// every attempt failed locally, before reaching any peer. The fix is our
	// reachability, not a different peer.
	ErrNoDialableCandidates = errors.New("no dialable candidates for selected hop set")

	// ErrBuildsRefused is the terminal outcome of a retry loop whose attempts
	// reached peers and were refused. Paired with ErrNoDialableCandidates so a
	// caller can tell which failure mode exhausted its retries.
	ErrBuildsRefused = errors.New("tunnel builds attempted and refused")
)

// IsGatewayUnreachable reports whether err is a failure to reach the first
// hop. The sentinel is checked first; the prose fallback keeps builders that
// carry no sentinel working, and is deliberately secondary so a wrapped
// sentinel always classifies deterministically.
func IsGatewayUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrGatewayUnreachable) {
		return true
	}
	return matchesGatewayUnreachability(err.Error())
}

// IsBuildRefused reports whether err is a refusal from a peer that was
// actually reached.
func IsBuildRefused(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrBuildRefused)
}

// gatewayUnreachableTerms are the prose markers of a failure to reach the
// first hop, kept only for builders that do not wrap a sentinel. They mirror
// the markers transport and i2np emit on the send path.
var gatewayUnreachableTerms = []string{
	"no transports available",
	"transport unavailable",
	"failed to establish outbound session",
	"failed to get session for gateway",
	"failed to send build request",
	"failed to send tunnel build message",
	"failed to dial",
	"connection refused",
	"no route to host",
}

func matchesGatewayUnreachability(s string) bool {
	s = strings.ToLower(s)
	for _, term := range gatewayUnreachableTerms {
		if strings.Contains(s, term) {
			return true
		}
	}
	return false
}
