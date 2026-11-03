package ntcp2

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/samber/oops"
)

// Pre-authentication admission control (finding 004 follow-up H-033).
//
// The handshake runs before the peer is authenticated, so every inbound TCP
// connection costs the router a goroutine, a socket, and the buffers the
// handshake itself allocates — paid by the router, requested by anyone. Two
// independent bounds keep that cost finite:
//
//   - a transport-wide cap on concurrent in-flight handshakes, so a flood from
//     many sources cannot exhaust the router, and
//   - a per-source cap, so a single host cannot consume the whole budget.
//
// Both are checked in the accept loop, before a handshake goroutine is spawned,
// and the reservation is released when that goroutine finishes. Refused
// connections are closed immediately: no handshake window, no junk read, no
// probing-resistance delay is spent on them.
//
// Spec basis (ntcp2.rst §"Session Request", DoS Mitigation): "Limit repeated or
// simultaneous connections from the same source." The spec names no numbers, so
// the limits are configuration and the defaults are ours.
//
// Distinct from go-noise's FailureTracker, which blacklists a source for
// repeated *protocol* failures. That mechanism cannot see a source that opens
// connections and never sends a handshake message at all, because nothing
// reaches a protocol error. The caps here bound exactly that case.

// errAdmissionGlobalFull reports that the transport-wide handshake budget is spent.
var errAdmissionGlobalFull = oops.New("NTCP2 inbound handshake budget exhausted")

// errAdmissionSourceFull reports that one source already holds its allowed share
// of the handshake budget.
var errAdmissionSourceFull = oops.New("NTCP2 inbound handshake per-source limit reached")

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
	if global > 0 {
		if a.inFlight.Add(1) > global {
			a.inFlight.Add(-1)
			return noopRelease, errAdmissionGlobalFull
		}
	}

	key := handshakeSourceKey(addr)
	if perSource > 0 && key != "" {
		a.mu.Lock()
		if int64(a.bySource[key])+1 > perSource {
			a.mu.Unlock()
			if global > 0 {
				a.inFlight.Add(-1)
			}
			return noopRelease, errAdmissionSourceFull
		}
		a.bySource[key]++
		a.mu.Unlock()
	}

	var once sync.Once
	release = func() {
		once.Do(func() {
			if global > 0 {
				a.inFlight.Add(-1)
			}
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
// Accepted connections carry a *ntcp2.Addr wrapper whose String() includes the
// (pre-handshake, placeholder) router hash, so the wrapper is unwrapped to the
// underlying TCP address first. Addresses that expose no IP (a pipe or a mock
// listener) fall back to the full address string, which keeps a single test
// fixture sharing one key rather than accidentally splitting into many.
func handshakeSourceKey(addr net.Addr) string {
	for addr != nil {
		// Unwrap the layers go-noise puts between the socket and the transport:
		// *ntcp2.Conn -> *ntcp2.Addr (which carries a placeholder router hash in
		// String()) -> *net.TCPAddr.
		if na, ok := addr.(*ntcp2.Addr); ok {
			addr = na.UnderlyingAddr()
			continue
		}
		if tcp, ok := addr.(*net.TCPAddr); ok {
			if tcp.IP == nil {
				return ""
			}
			return tcp.IP.String()
		}
		if ipAddr, ok := addr.(*net.IPAddr); ok {
			if ipAddr.IP == nil {
				return ""
			}
			return ipAddr.IP.String()
		}
		// A transport without IP addresses (a pipe in tests, a custom listener):
		// key on the whole address so failures are still attributed to something
		// stable rather than silently bypassing the per-source limit.
		s := addr.String()
		if s == "" {
			return ""
		}
		return s
	}
	return ""
}
