package ssu2

import (
	"net"
	"sync"
	"sync/atomic"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/samber/oops"
)

// Pre-authentication admission control for inbound SSU2 (finding 005).
//
// go-noise hands the transport a connection as soon as a SessionRequest parses;
// nothing in it has been authenticated at that point. The ephemeral key needs no
// valid key material, the source address can be spoofed, and the responder
// handshake that follows costs this router a goroutine, per-session listener
// state and a handshake timeout window. Without a bound, one unauthenticated
// packet per source is enough to keep the router spending on handshakes.
//
// Two independent caps keep that cost finite, mirroring the NTCP2 transport:
//
//   - a transport-wide cap on concurrent in-flight responder handshakes, so a
//     flood from many sources cannot exhaust the router, and
//   - a per-source cap, so one host cannot consume the whole budget.
//
// Both are checked in the accept loop before a handshake goroutine is spawned,
// and the reservation is released when that goroutine finishes. Refused
// connections are torn down with CloseImmediate: no handshake window is opened
// for them and no Termination destroy wait is paid.
//
// Distinct from the session limit, which is only checked after a handshake
// succeeds: reserving a session slot pre-handshake would let an attacker hold
// every slot in the pool for the duration of the handshake timeout.
//
// Distinct from the go-noise listener's own per-IP SessionRequest rate limiter,
// which bounds the packet rate but says nothing about how many handshakes are
// outstanding at once.

// errAdmissionGlobalFull reports that the transport-wide handshake budget is spent.
var errAdmissionGlobalFull = oops.New("SSU2 inbound handshake budget exhausted")

// errAdmissionSourceFull reports that one source already holds its allowed share
// of the handshake budget.
var errAdmissionSourceFull = oops.New("SSU2 inbound handshake per-source limit reached")

// handshakeAdmission tracks the reservations described above.
//
// The in-flight count is a single atomic rather than a channel semaphore: the
// limits are read from the transport's live configuration, which SetIdentity
// swaps, so a resized cap must take effect on the next admission instead of
// requiring the semaphore to be rebuilt while handshakes are in flight.
type handshakeAdmission struct {
	// inFlight is the number of handshakes currently admitted transport-wide.
	inFlight atomic.Int64
	// bySource counts in-flight handshakes per source key. Guarded by mu; an
	// entry is deleted as soon as its count reaches zero so the map cannot
	// itself grow without bound under a many-sources flood.
	mu       sync.Mutex
	bySource map[string]int
}

func newHandshakeAdmission() *handshakeAdmission {
	return &handshakeAdmission{bySource: make(map[string]int)}
}

// admit reserves a handshake slot for a connection.
//
// Returns a release function the caller must invoke when the handshake
// finishes. release is safe to call more than once and safe to call when admit
// failed (it is a no-op then). global and perSource are the effective limits at
// the moment of the call; non-positive values disable the corresponding bound.
//
// A nil receiver admits everything and returns a no-op release, so transports
// built without an admission controller (test fixtures assembled from struct
// literals) keep working.
func (a *handshakeAdmission) admit(addr net.Addr, global, perSource int64) (release func(), err error) {
	if a == nil {
		return noopRelease, nil
	}

	// Always accounted, even when the global bound is disabled, so the metrics
	// snapshot reports the real number of handshakes running rather than zero
	// whenever an operator turns the cap off.
	//
	// Increment-then-test is what makes the cap exact without a lock: an admit
	// that would exceed the budget observes its own post-increment value above
	// the limit, backs its reservation straight back out, and refuses.
	// Concurrent admits may transiently overshoot the counter, but never admit
	// more than global handshakes.
	if a.inFlight.Add(1) > global && global > 0 {
		a.inFlight.Add(-1)
		return noopRelease, errAdmissionGlobalFull
	}

	key := handshakeSourceKey(addr)
	if perSource > 0 && key != "" {
		a.mu.Lock()
		if int64(a.bySource[key])+1 > perSource {
			a.mu.Unlock()
			a.inFlight.Add(-1)
			return noopRelease, errAdmissionSourceFull
		}
		a.bySource[key]++
		a.mu.Unlock()
	}

	var once sync.Once
	release = func() {
		once.Do(func() {
			a.inFlight.Add(-1)
			if perSource > 0 && key != "" {
				a.mu.Lock()
				if a.bySource[key]--; a.bySource[key] <= 0 {
					delete(a.bySource, key)
				}
				a.mu.Unlock()
			}
		})
	}
	return release, nil
}

// current returns the transport-wide in-flight count. Used by tests and metrics.
func (a *handshakeAdmission) current() int64 {
	if a == nil {
		return 0
	}
	return a.inFlight.Load()
}

// sourceCount returns how many handshakes addr's source currently holds.
func (a *handshakeAdmission) sourceCount(addr net.Addr) int {
	if a == nil {
		return 0
	}
	key := handshakeSourceKey(addr)
	if key == "" {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.bySource[key]
}

func noopRelease() {}

// handshakeSourceKey reduces a connection's remote address to the identity a
// per-source limit should be keyed on: the IP address, without the port.
//
// Accepted connections carry a *ssu2noise.SSU2Addr whose String() includes the
// (pre-handshake, placeholder) router hash and the connection ID, so the wrapper
// is unwrapped to the underlying UDP address first. Addresses that expose no IP
// (a mock listener, a unix datagram socket) fall back to the full address string,
// which keeps a single test fixture sharing one key rather than accidentally
// splitting into many.
func handshakeSourceKey(addr net.Addr) string {
	for addr != nil {
		if sa, ok := addr.(*ssu2noise.SSU2Addr); ok {
			addr = sa.UnderlyingAddr()
			continue
		}
		if udp, ok := addr.(*net.UDPAddr); ok {
			if udp.IP == nil {
				return ""
			}
			return udp.IP.String()
		}
		if ipAddr, ok := addr.(*net.IPAddr); ok {
			if ipAddr.IP == nil {
				return ""
			}
			return ipAddr.IP.String()
		}
		// An address without an IP: key on the whole string so failures are still
		// attributed to something stable rather than bypassing the per-source cap.
		s := addr.String()
		if s == "" {
			return ""
		}
		return s
	}
	return ""
}
