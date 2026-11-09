package transport

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
)

// ──────────────────────────────────────────────────────────────────────────────
// Session message queue sizing
// ──────────────────────────────────────────────────────────────────────────────

// SessionCore owns the two I2NP queues every transport session shares. Both
// directions get the same depth so a session buffers an equal burst of
// outbound (app -> wire) and inbound (wire -> app) messages. 256 messages is
// enough to absorb a tunnel-latency spike without pinning much memory per
// session, and small enough that a router holding hundreds of sessions does
// not exhaust itself queueing work it can never deliver.
//
// Moved from: sessioncore.go
const (
	// defaultSessionQueueDepth is the buffered capacity of both the send queue
	// and the receive channel.
	defaultSessionQueueDepth = 256

	// defaultInboundRateLimit is the sustained messages-per-second an inbound
	// session may deliver before the limiter starts throttling it. It matches
	// the queue depth so one full receive queue can be drained in a second.
	defaultInboundRateLimit = 256

	// defaultInboundRateBurst is how many messages the inbound limiter lets
	// through instantaneously before falling back to the sustained rate: twice
	// the sustained rate, so a burst that merely fills the receive queue is not
	// immediately throttled.
	defaultInboundRateBurst = 512
)

// ──────────────────────────────────────────────────────────────────────────────
// Queue wait and poll intervals
// ──────────────────────────────────────────────────────────────────────────────

// The two intervals below bound how long a session waits on its own queues.
// Neither is a protocol value: they are tuning knobs that trade promptness
// against busy-wait cost. They are polled rather than signalled because the
// queue depth is already the signal, and a ticker is the cheapest way to
// re-check it.
//
// Moved from: sessioncore.go
const (
	// sendQueueSendTimeout bounds how long QueueSendI2NP waits for space in the
	// send queue before dropping the message. Long enough to ride out a
	// transient slow write to the peer, short enough that a stuck connection
	// surfaces as dropped messages rather than an ever-growing queue.
	sendQueueSendTimeout = 500 * time.Millisecond

	// sendQueueDrainPollInterval is how often DrainSendQueue re-checks the queue
	// depth while waiting for it to empty during session close.
	sendQueueDrainPollInterval = 10 * time.Millisecond
)

// ──────────────────────────────────────────────────────────────────────────────
// Transport muxer accept loop
// ──────────────────────────────────────────────────────────────────────────────

// Muxed transports share one accept channel and one pool of accept goroutines.
// The constants here size and pace that machinery; they are not protocol
// values.
//
// Moved from: multi.go
const (
	// acceptChanBufferPerTransport is how many buffered results each muxed
	// transport gets in the shared accept channel. The buffer must never be the
	// thing that blocks an accept goroutine, or one slow consumer of Accept()
	// would stall every transport instead of just the one whose connection is
	// ready.
	acceptChanBufferPerTransport = 4

	// acceptRetryBackoff is the pause after a transient accept error (EMFILE and
	// friends) before retrying. It keeps an erroring listener from spinning hot
	// while staying short enough that a recovered listener resumes promptly.
	acceptRetryBackoff = 50 * time.Millisecond

	// acceptGoroutineWaitTimeout bounds how long Close() waits for the accept
	// goroutines to exit once the transports are closed. Exceeding it is a leak
	// to be reported, not a reason to hang shutdown.
	acceptGoroutineWaitTimeout = 3 * time.Second

	// failedPeersCleanupInterval is how often the muxer sweeps expired entries
	// out of the failed-peer cooldown map so it cannot grow without bound over
	// the router's lifetime. It is coarser than the cooldown itself by design:
	// a sweep only has to keep the map bounded, not expire entries on time,
	// because the cooldown check compares timestamps anyway.
	failedPeersCleanupInterval = 5 * time.Minute
)

// ──────────────────────────────────────────────────────────────────────────────
// On-disk file permissions
// ──────────────────────────────────────────────────────────────────────────────

// secureFilePermissions is the mode used for every file this transport writes
// that contains key material: owner read/write only. Aliased from lib/config,
// which owns the router-wide policy, so the transport cannot write a key file
// with a looser mode than the rest of the router.
//
// Moved from: persistent_config.go
const secureFilePermissions = config.SecureFilePermissions
