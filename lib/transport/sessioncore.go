package transport

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"golang.org/x/time/rate"
)

// AcceptedConn is a marker type wrapping a connection that has been delivered to Accept().
// It prevents promotion to a session (avoiding dual ownership). This type is used by
// SessionRegistry and transport implementations (NTCP2, SSU2) during the session lifecycle.
// The marker serves only for type identification; the actual connection data is stored
// in the Value field or accessed via any embedded type.
//
// This type is shared across the transport package and its subpackages (ntcp2, ssu2)
// to eliminate type confusion from multiple independent definitions of the same concept.
type AcceptedConn struct {
	Value interface{}
}

// DefaultSendQueueDrainTimeout is the maximum time to wait for queued messages
// to be sent before the session is closed. Used by DrainSendQueue.
const DefaultSendQueueDrainTimeout = 2 * time.Second

// SessionCore contains the shared I2NP message queue, bandwidth tracking,
// and lifecycle management fields used by both NTCP2Session and SSU2Session.
// This struct is embedded (not composed) by transport sessions to enable
// shared method implementations and reduce duplication across transports.
//
// Thread-safe: atomic counters for bandwidth; channels for queues; context
// and sync.Once for lifecycle; Mutex guards for callbacks.
type SessionCore struct {
	// I2NP message queues: both are 256-buffered channels for balanced latency
	// and throughput. sendQueue is the outbound queue (app → wire); recvChan
	// is the inbound queue (wire → app).
	sendQueue chan i2np.Message
	recvChan  chan i2np.Message

	// Queue size tracking: atomic counter of messages in-flight or queued
	// (incremented on queue, decremented on send/receive completion).
	sendQueueSize int32

	// Bandwidth statistics (atomic counters, accessed without locks).
	// bytesSent and bytesReceived track cumulative bytes since session start.
	// droppedMessages tracks inbound messages rejected due to full recvChan.
	bytesSent       uint64
	bytesReceived   uint64
	droppedMessages uint64

	// Lifecycle management.
	ctx    context.Context    // session-local context (canceled on close)
	cancel context.CancelFunc // cancels ctx

	closeOnce sync.Once      // ensures Close() runs exactly once
	wg        sync.WaitGroup // synchronizes background workers

	// Cleanup callback: called exactly once when session closes, protected by
	// callbackMu to prevent concurrent mutation.
	callbackMu      sync.Mutex
	cleanupCallback func()
	cleanupOnce     sync.Once

	// Per-session inbound I2NP rate limiter: 256 msg/s sustained, burst 512.
	// Protects against message-flood DoS from a single peer.
	inboundLimiter *rate.Limiter

	// Logging: pointer to a pre-formatted logger entry with component/remote_addr fields.
	logger *logger.Entry
}

// NewSessionCore creates a core session with the given context and logger.
// This is called by NTCP2Session and SSU2Session constructors.
// The context should be cancellable (typically via context.WithCancel).
//
// Callers must manually set any additional fields (e.g., rekeyState, congestionCtrl)
// after construction.
func NewSessionCore(ctx context.Context, logger *logger.Entry) *SessionCore {
	sessionCtx, cancelFunc := context.WithCancel(ctx)
	return &SessionCore{
		sendQueue:      make(chan i2np.Message, 256),
		recvChan:       make(chan i2np.Message, 256),
		ctx:            sessionCtx,
		cancel:         cancelFunc,
		inboundLimiter: rate.NewLimiter(256, 512),
		logger:         logger,
	}
}

// NewSessionLogger creates a logger entry with standard session identity fields.
func NewSessionLogger(base *logger.Entry, component, remoteAddr string) *logger.Entry {
	return base.WithFields(map[string]interface{}{
		"component":   component,
		"remote_addr": remoteAddr,
	})
}

// NewSessionCoreWithLogger builds both a session-scoped logger and SessionCore.
func NewSessionCoreWithLogger(ctx context.Context, base *logger.Entry, component, remoteAddr string) (*SessionCore, *logger.Entry) {
	sessionLogger := NewSessionLogger(base, component, remoteAddr)
	return NewSessionCore(ctx, sessionLogger), sessionLogger
}

// QueueSendI2NP queues an I2NP message to be sent over the session.
// Returns an error if the session is closed or the send queue fills after
// a 500ms timeout. Thread-safe: uses atomic operations and channels.
//
// Note: sendQueueSize is incremented before the channel send to ensure
// SendQueueSize() always reflects in-flight + queued messages. On failure
// (ctx.Done or timeout), sendQueueSize is decremented.
func (sc *SessionCore) QueueSendI2NP(msg i2np.Message) error {
	// Increment atomically before channel send.
	atomic.AddInt32(&sc.sendQueueSize, 1)

	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()

	select {
	case sc.sendQueue <- msg:
		return nil
	case <-sc.ctx.Done():
		atomic.AddInt32(&sc.sendQueueSize, -1)
		return oops.Errorf("session closed, message dropped (type=%d)", msg.Type())
	case <-timer.C:
		atomic.AddInt32(&sc.sendQueueSize, -1)
		return oops.Errorf("send queue full, message dropped (type=%d)", msg.Type())
	}
}

// SendQueueSize returns how many I2NP messages are currently queued or in-flight.
// The count reflects messages added via QueueSendI2NP but not yet fully sent
// (decremented by the send worker after writing to the connection).
func (sc *SessionCore) SendQueueSize() int {
	return int(atomic.LoadInt32(&sc.sendQueueSize))
}

// GetBandwidthStats returns the total bytes sent and received by this session.
// Each counter is read atomically, but the pair is not a consistent snapshot:
// a concurrent send/receive between the two reads may cause slight skew.
// This is acceptable for monitoring; use a mutex if point-in-time consistency
// is required.
func (sc *SessionCore) GetBandwidthStats() (bytesSent, bytesReceived uint64) {
	return atomic.LoadUint64(&sc.bytesSent), atomic.LoadUint64(&sc.bytesReceived)
}

// ReadNextI2NP blocks until the next fully-received I2NP message is available,
// or until the session closes. Returns an error if ctx is canceled.
// Thread-safe: uses channels and context.
func (sc *SessionCore) ReadNextI2NP() (i2np.Message, error) {
	select {
	case msg := <-sc.recvChan:
		return msg, nil
	case <-sc.ctx.Done():
		return nil, ErrSessionClosed
	}
}

// SetCleanupCallback sets a callback function that will be called exactly once
// when the session closes. Thread-safe: protected by callbackMu.
// If a callback is already set, it is replaced.
func (sc *SessionCore) SetCleanupCallback(callback func()) {
	sc.callbackMu.Lock()
	sc.cleanupCallback = callback
	sc.callbackMu.Unlock()
}

// callCleanupCallback calls the cleanup callback if set, ensuring it runs
// exactly once via cleanupOnce. Thread-safe.
func (sc *SessionCore) CallCleanupCallback() {
	sc.cleanupOnce.Do(func() {
		sc.callbackMu.Lock()
		cb := sc.cleanupCallback
		sc.callbackMu.Unlock()
		if cb != nil {
			cb()
		}
	})
}

// recordSendQueueDecrement records that a message has been fully sent.
// Called by send workers to decrement sendQueueSize after writing to the wire.
func (sc *SessionCore) recordSendQueueDecrement() {
	atomic.AddInt32(&sc.sendQueueSize, -1)
}

// recordBandwidth records bytes sent or received via atomic add.
// Called by send/receive workers to update bandwidth counters.
func (sc *SessionCore) recordBandwidth(sent, received uint64) {
	if sent > 0 {
		atomic.AddUint64(&sc.bytesSent, sent)
	}
	if received > 0 {
		atomic.AddUint64(&sc.bytesReceived, received)
	}
}

// recordDroppedMessage increments the dropped-message counter.
// Called when an inbound message cannot be queued (backpressure).
func (sc *SessionCore) RecordDroppedMessage() {
	atomic.AddUint64(&sc.droppedMessages, 1)
}

// DroppedMessages returns the count of inbound messages dropped due to
// backpressure (full recvChan).
func (sc *SessionCore) DroppedMessages() uint64 {
	return atomic.LoadUint64(&sc.droppedMessages)
}

func addUint64Atomic(counter *uint64, delta uint64) uint64 {
	return atomic.AddUint64(counter, delta)
}

func addInt32Atomic(counter *int32, delta int32) int32 {
	return atomic.AddInt32(counter, delta)
}

// AddToBytesSent adds delta to the cumulative bytes-sent counter (atomic).
// Called by transport writers after successful frame transmission.
func (sc *SessionCore) AddToBytesSent(delta uint64) {
	addUint64Atomic(&sc.bytesSent, delta)
}

// AddToBytesReceived adds delta to the cumulative bytes-received counter (atomic).
// Called by transport readers after successful frame reception.
func (sc *SessionCore) AddToBytesReceived(delta uint64) {
	addUint64Atomic(&sc.bytesReceived, delta)
}

// AddToSendQueueSize adds delta to the send queue size (atomic).
// delta is typically -1 (dequeued) or +1 (enqueued). Returns new size.
func (sc *SessionCore) AddToSendQueueSize(delta int32) int32 {
	return addInt32Atomic(&sc.sendQueueSize, delta)
}

// GetContext returns the session's context. Used by transport workers to
// check for cancellation and set read/write deadlines.
func (sc *SessionCore) GetContext() context.Context {
	return sc.ctx
}

// Cancel cancels the session's context, signaling all workers to stop.
// Idempotent: safe to call multiple times.
func (sc *SessionCore) Cancel() {
	sc.cancel()
}

// Logger returns the session's logger entry. Callers can use WithFields
// to add contextual fields.
func (sc *SessionCore) Logger() *logger.Entry {
	return sc.logger
}

// WaitGroup returns the session's WaitGroup for coordinating worker shutdown.
// Callers (typically Send/ReceiveWorker) call Add(1) on startup and Done()
// before exiting.
func (sc *SessionCore) WaitGroup() *sync.WaitGroup {
	return &sc.wg
}

// InboundLimiter returns the rate limiter for inbound I2NP messages.
// Callers can use it to enforce per-session rate limits.
func (sc *SessionCore) InboundLimiter() *rate.Limiter {
	return sc.inboundLimiter
}

// SendQueue returns the send queue channel for direct access by send workers.
// Workers read from this channel to send queued messages.
func (sc *SessionCore) SendQueue() chan i2np.Message {
	return sc.sendQueue
}

// RecvChan returns the receive channel for direct access by receive workers.
// Workers write to this channel when messages are fully received.
func (sc *SessionCore) RecvChan() chan i2np.Message {
	return sc.recvChan
}

// CloseOnce returns the sync.Once used to ensure Close() runs exactly once.
// Used by transport sessions' Close() implementations.
func (sc *SessionCore) CloseOnce() *sync.Once {
	return &sc.closeOnce
}

// DrainSendQueue waits for the send queue to empty, up to the given timeout.
// Returns true if the queue drained successfully, false if the timeout expired.
//
// Used during session close to gracefully wait for in-flight messages to be
// sent before terminating the connection. Callers should not hold locks while
// calling this method.
func (sc *SessionCore) DrainSendQueue(timeout time.Duration) bool {
	if sc.SendQueueSize() == 0 {
		return true
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline.C:
			return false
		case <-ticker.C:
			if sc.SendQueueSize() == 0 {
				return true
			}
		}
	}
}

// DiscardRemaining non-blockingly drains and discards all messages left in the send queue.
// This ensures sendQueueSize reaches zero so subsequent queue checks don't hang.
// Used during session cleanup to ensure worker goroutines can exit cleanly.
func (sc *SessionCore) DiscardRemaining() {
	for {
		select {
		case <-sc.SendQueue():
			sc.AddToSendQueueSize(-1)
		default:
			return
		}
	}
}
