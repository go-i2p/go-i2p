package ntcp2

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NTCP2Session represents an active NTCP2 connection session with a remote peer, managing message queues, bandwidth tracking, and message-count based session replacement state.
// A session is the transport-level connection between two routers; it wraps
// the Noise-encrypted TCP connection and satisfies transport.TransportSession.
// It embeds *transport.SessionCore for shared queue and bandwidth logic.
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for the protocol.
// See also [NTCP2Transport] and [transport.SessionCore].
type NTCP2Session struct {
	// Shared session core fields: queues, bandwidth tracking, lifecycle, and callbacks.
	// This embeds *SessionCore, so callers can call QueueSendI2NP, ReadNextI2NP, etc. directly.
	*transport.SessionCore

	// Underlying connection (uses net.Conn interface per guidelines)
	conn   net.Conn   // Will be *ntcp2.NTCP2Conn internally
	connMu sync.Mutex // protects conn field

	// Message-count state — tracks traffic to enforce the session replacement threshold
	rekeyState *rekeyState

	// Error tracking for receive worker
	errorMu   sync.Mutex
	lastError error

	// closeRequested is set when the close path has started, either through an
	// explicit Close() or through the automatic teardown an error triggers.
	// Idle maintenance uses it as a failsafe: a session whose context is done
	// and whose close has not started is a session whose socket, transport
	// registry entry and muxer slot are still held (finding 006).
	closeRequested atomic.Bool

	// RouterInfo callback (called when a RouterInfo block is received from peer)
	routerInfoMu       sync.Mutex
	routerInfoCallback func(riBytes []byte, floodRequested bool)

	// peerOptions holds the most recent valid Options block received from the
	// peer (handshake message 2/3 or data phase). Recorded for observability and
	// for outbound padding decisions; see [NTCP2Session.PeerOptions].
	peerOptionsMu sync.Mutex
	peerOptions   *OptionsData

	createdAtUnixNano int64
	lastSendUnixNano  int64
	lastRecvUnixNano  int64
}

// NewNTCP2Session creates a new NTCP2 session and immediately starts background
// send/receive workers. Use NewNTCP2SessionDeferred + StartWorkers for cases
// where worker startup should be delayed (e.g., dedup via LoadOrStore).
func NewNTCP2Session(conn net.Conn, ctx context.Context, logger *logger.Entry) *NTCP2Session {
	session := NewNTCP2SessionDeferred(conn, ctx, logger)
	session.StartWorkers()
	return session
}

// NewNTCP2SessionDeferred creates a new NTCP2 session without starting background
// workers. Call StartWorkers() after confirming the session will be used (e.g.,
// after winning a LoadOrStore race). This prevents spawning goroutines for sessions
// that will be immediately discarded.
func NewNTCP2SessionDeferred(conn net.Conn, ctx context.Context, logger *logger.Entry) *NTCP2Session {
	core, sessionLogger := transport.NewSessionCoreWithLogger(ctx, logger, "ntcp2_session", conn.RemoteAddr().String())
	sessionLogger.Debug("Creating new NTCP2 session")

	session := &NTCP2Session{
		SessionCore: core,
		conn:        conn,
		rekeyState:  newRekeyState(),
	}
	now := time.Now().UnixNano()
	atomic.StoreInt64(&session.createdAtUnixNano, now)
	atomic.StoreInt64(&session.lastSendUnixNano, now)
	atomic.StoreInt64(&session.lastRecvUnixNano, now)

	sessionLogger.Info("NTCP2 session created (deferred workers)")
	return session
}

// StartWorkers launches the background send and receive goroutines.
// Must be called exactly once after the session is confirmed as the active session.
func (s *NTCP2Session) StartWorkers() {
	s.Logger().Debug("Starting send and receive workers")
	s.WaitGroup().Add(2)
	go s.sendWorker()
	go s.receiveWorker()
	s.Logger().Debug("NTCP2 session workers started")
}

// ReadNextI2NP blocking reads the next fully received I2NP message from this session.
// If a critical error occurred during receive processing, it is returned instead
// of waiting for more messages.
func (s *NTCP2Session) ReadNextI2NP() (i2np.Message, error) {
	select {
	case msg := <-s.RecvChan():
		return msg, nil
	case <-s.GetContext().Done():
		if err := s.getError(); err != nil {
			return nil, err
		}
		return nil, s.GetContext().Err()
	}
}

// Close closes the session cleanly.
// It first waits briefly for the send queue to drain
// before sending an encrypted termination block (reason 0 = normal close) and
// closing the connection. This gives queued messages a chance to be transmitted
// rather than being silently dropped.
func (s *NTCP2Session) Close() error {
	return s.CloseWithReason(TerminationNormalClose)
}

// CloseWithReason closes the session with the specified termination reason code.
// If the reason is an AEAD failure (reason 4), the termination block is NOT sent
// because the cipher state may be corrupted — instead, only probing-resistance
// junk-read is performed on the underlying connection.
// For all other reasons, an encrypted termination block is sent through the
// NTCP2 connection's Noise cipher state (via conn.Write), which ensures it is
// encrypted and has a SipHash-obfuscated length prefix like any other data-phase
// frame. No plaintext termination blocks are ever sent.
// Spec reference: https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst
func (s *NTCP2Session) CloseWithReason(reason byte) error {
	var err error
	// Mark the teardown as started before anything else: the idle-maintenance
	// failsafe uses closeRequested to tell "cancelled and already tearing down"
	// apart from "cancelled with the socket, registry entry and session slot
	// still held" (finding 006). sync.Once below makes the body idempotent.
	s.closeRequested.Store(true)
	s.CloseOnce().Do(func() {
		s.logSessionLifecycleSummary(reason)
		s.Logger().WithField("reason", TerminationReasonString(reason)).Info("Closing NTCP2 session")

		// Wait for send queue to drain before canceling context.
		// The sendWorker is still running at this point, so queued messages
		// can still be transmitted.
		s.drainSendQueue()

		// Send encrypted termination block before closing, unless the
		// reason is an AEAD failure (cipher state may be corrupted).
		if IsAEADFailureReason(reason) {
			s.Logger().Debug("AEAD failure reason — skipping termination block, applying probing resistance")
			s.connMu.Lock()
			conn := s.conn
			s.connMu.Unlock()
			if conn != nil {
				raw := extractRawConn(conn)
				applyProbingResistance(raw)
			}
		} else {
			// On an error-driven teardown the send worker may be parked writing
			// to a peer that stopped reading, and go-noise serialises writes, so
			// this block would queue behind that parked write. Cancelling pending
			// writes first unblocks the worker, which then exits on the cancelled
			// context. Without it Close stalls for as long as the parked write
			// holds the socket — keeping the fd, the registry entry and the
			// session slot alive, which is the failure this teardown exists to
			// clear.
			//
			// A healthy close (context still live) must not do this: a worker may
			// legitimately still be flushing the last queued message after the
			// drain, and cancelling it would truncate the graceful shutdown.
			if !s.IsAlive() {
				s.cancelPendingWrites()
			}
			s.sendEncryptedTermination(reason)
		}

		s.Cancel()
		s.connMu.Lock()
		conn := s.conn
		s.connMu.Unlock()
		if conn != nil {
			// Unblock the receive worker before closing, or Close() stalls.
			//
			// go-noise's (*Conn).Close zeroes its buffered plaintext under the
			// connection's read mutex, and the receive worker holds that mutex for
			// the whole blocking Read — which is armed with the 5-minute
			// ntcp2ReadDeadline. Closing first would therefore make Close wait for
			// the parked Read to time out, holding the session (and the transport's
			// shutdown) for minutes after the peer is gone.
			//
			// An expired read deadline returns the parked Read immediately; the
			// worker then exits on its own because Cancel() above already closed the
			// session context.
			if deadlineErr := conn.SetReadDeadline(time.Now()); deadlineErr != nil {
				s.Logger().WithError(deadlineErr).
					Debug("Failed to set closing read deadline on NTCP2 connection")
			}
			err = conn.Close()
			if err != nil {
				s.Logger().WithError(err).Warn("Error closing connection")
			}
		}
		s.Logger().Debug("Waiting for session workers to complete")
		s.WaitGroup().Wait()

		// Call cleanup callback to remove session from transport map
		s.CallCleanupCallback()
		s.Logger().Info("NTCP2 session closed successfully")
	})
	return err
}

func (s *NTCP2Session) markSendActivity() {
	atomic.StoreInt64(&s.lastSendUnixNano, time.Now().UnixNano())
}

func (s *NTCP2Session) markRecvActivity() {
	atomic.StoreInt64(&s.lastRecvUnixNano, time.Now().UnixNano())
}

func durationSinceUnixNano(ts int64) time.Duration {
	if ts <= 0 {
		return 0
	}
	return time.Since(time.Unix(0, ts))
}

// shouldCloseForIdle reports whether both send and receive directions have been
// idle longer than the supplied Java-style maintenance window.
func (s *NTCP2Session) shouldCloseForIdle(now time.Time, expire time.Duration) bool {
	if expire <= 0 {
		return false
	}
	idleSend := now.Sub(time.Unix(0, atomic.LoadInt64(&s.lastSendUnixNano)))
	idleRecv := now.Sub(time.Unix(0, atomic.LoadInt64(&s.lastRecvUnixNano)))
	return idleSend > expire && idleRecv > expire
}

func (s *NTCP2Session) logSessionLifecycleSummary(reason byte) {
	age := durationSinceUnixNano(atomic.LoadInt64(&s.createdAtUnixNano))
	idleSend := durationSinceUnixNano(atomic.LoadInt64(&s.lastSendUnixNano))
	idleRecv := durationSinceUnixNano(atomic.LoadInt64(&s.lastRecvUnixNano))
	bytesSent, bytesReceived := s.GetBandwidthStats()

	fields := map[string]interface{}{
		"close_reason":       TerminationReasonString(reason),
		"last_error":         s.getError(),
		"session_age_ms":     age.Milliseconds(),
		"idle_since_send_ms": idleSend.Milliseconds(),
		"idle_since_recv_ms": idleRecv.Milliseconds(),
		"bytes_sent":         bytesSent,
		"bytes_received":     bytesReceived,
		"dropped_messages":   s.DroppedMessages(),
	}

	s.Logger().WithFields(fields).Debug("NTCP2 session lifecycle summary")
}

// DetachConn clears the session's reference to the underlying connection,
// preventing Close() from closing the socket. This is used when a session
// loses a promotion race — the winner owns the socket, so the loser must
// not close it. Workers will still stop cleanly when Close() cancels the
// session context.
func (s *NTCP2Session) DetachConn() {
	s.connMu.Lock()
	s.conn = nil
	s.connMu.Unlock()
}

// sendEncryptedTermination sends an encrypted termination block through the
// NTCP2 connection's Noise cipher state. The block is encrypted and framed
// by conn.Write, which applies AEAD encryption and SipHash length obfuscation,
// ensuring no plaintext termination block ever appears on the wire.
// This is a best-effort operation: errors are logged but do not prevent the
// session from closing.
func (s *NTCP2Session) sendEncryptedTermination(reason byte) {
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn == nil {
		return
	}

	// ntcp2.rst:1691-1694: the Termination block carries the number of valid
	// AEAD data-phase frames received (the current receive nonce), 0 if the
	// error occurred in the handshake phase.
	frames := validFramesReceived(conn)
	block := BuildTerminationBlockWithFrames(reason, frames)
	s.Logger().WithFields(map[string]interface{}{
		"reason":       TerminationReasonString(reason),
		"block_size":   len(block),
		"valid_frames": frames,
	}).Debug("Sending encrypted termination block")

	// go-noise serialises writes, so this block queues behind whatever the send
	// worker has in flight. Arm a short deadline so a parked worker cannot make
	// Close wait for it; the deadline is bounded rather than expired so this
	// write itself still gets a chance to reach the wire.
	if deadlineErr := conn.SetWriteDeadline(time.Now().Add(ntcp2TerminationWriteTimeout)); deadlineErr != nil {
		s.Logger().WithError(deadlineErr).Debug("Failed to set termination block write deadline")
	}

	if _, writeErr := conn.Write(block); writeErr != nil {
		s.Logger().WithError(writeErr).Debug("Failed to send encrypted termination block (best-effort)")
	} else {
		s.Logger().Debug("Encrypted termination block sent successfully")
	}
}

// cancelPendingWrites arms an expired write deadline so a send worker parked in
// a blocking write returns immediately. It must only be called while tearing the
// session down, since it discards whatever is mid-flight.
func (s *NTCP2Session) cancelPendingWrites() {
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn == nil {
		return
	}
	if err := conn.SetWriteDeadline(time.Now()); err != nil {
		s.Logger().WithError(err).Debug("Failed to cancel pending NTCP2 writes before close")
	}
}

// drainSendQueue waits for the send queue to empty before close.
// This is called before canceling the session context so the sendWorker can
// still process queued messages.
func (s *NTCP2Session) drainSendQueue() {
	// Once the session context is cancelled the send worker has stopped (or is
	// stopping), so nothing left in the queue can reach the wire. Waiting here
	// would only delay the teardown that an error path just scheduled.
	if !s.IsAlive() {
		return
	}

	queueSize := s.SendQueueSize()
	if queueSize == 0 {
		return
	}

	s.Logger().WithField("queue_size", queueSize).Debug("Draining send queue before close")

	drained := s.SessionCore.DrainSendQueue(transport.DefaultSendQueueDrainTimeout)
	if !drained {
		remaining := s.SendQueueSize()
		if remaining > 0 {
			s.Logger().WithField("remaining", remaining).Warn("Send queue drain timeout, dropping remaining messages")
		}
	}
}

// sendWorker handles sending I2NP messages over the NTCP2 connection.
func (s *NTCP2Session) sendWorker() {
	defer s.WaitGroup().Done()
	s.Logger().Debug("Send worker started")
	defer s.Logger().Debug("Send worker stopped")

	nextMetaAt := time.Now().Add(ntcp2NextMetaInterval())

	for {
		select {
		case msg := <-s.SendQueue():
			if !s.processSendQueueMessage(msg, &nextMetaAt) {
				s.discardRemainingMessages()
				return
			}
		case <-s.GetContext().Done():
			s.discardRemainingMessages()
			return
		}
	}
}

// Java I2P-style NTCP2 DateTime metadata cadence.
// Metadata is emitted on outbound data writes when due, with half-to-full
// jitter around the base frequency.
const ntcp2MetaFrequency = 45 * time.Minute

func ntcp2NextMetaInterval() time.Duration {
	return nextMetaIntervalWithRand(rand.Int63n)
}

func nextMetaIntervalWithRand(randInt63n func(int64) int64) time.Duration {
	half := ntcp2MetaFrequency / 2
	return half + time.Duration(randInt63n(int64(half)))
}

// discardRemainingMessages drains and discards any messages left in the send queue
// after the worker decides to stop. This delegates to the SessionCore shared implementation.
func (s *NTCP2Session) discardRemainingMessages() {
	s.SessionCore.DiscardRemaining()
}

// processSendQueueMessage processes a single I2NP message from the send queue.
// Returns false if an error occurred and the worker should stop, true otherwise.
func (s *NTCP2Session) processSendQueueMessage(msg i2np.Message, nextMetaAt *time.Time) bool {
	newSize := s.AddToSendQueueSize(-1)
	s.Logger().WithFields(map[string]interface{}{
		"message_type":       msg.Type(),
		"remaining_in_queue": newSize,
	}).Debug("Processing message from send queue")

	framedData, err := s.frameMessage(msg)
	if err != nil {
		return false
	}
	if framedData == nil {
		// frameMessage dropped an oversized message rather than fragmenting
		// it across frames; keep the worker running with the next message.
		return true
	}

	framedData = s.attachDateTimeMetadataIfDue(framedData, nextMetaAt)

	return s.writeFramedData(framedData)
}

// attachDateTimeMetadataIfDue prepends the periodic DateTime block (type 0) to
// an outbound frame when the next metadata interval is due.
//
// The block is only attached when the combined payload still fits in one
// ChaChaPoly frame: if the I2NP block already fills a frame, adding the
// DateTime block would push the write past the single-frame limit, and the
// go-noise write path would fragment the I2NP message across frames, which
// ntcp2.rst:1626-1628 forbids. In that case the metadata is deferred to a
// later frame rather than the message being dropped.
func (s *NTCP2Session) attachDateTimeMetadataIfDue(framedData []byte, nextMetaAt *time.Time) []byte {
	if time.Now().Before(*nextMetaAt) {
		return framedData
	}
	withMeta := append(SerializeBlocks(NewDateTimeBlock()), framedData...)
	if !s.fitsInSingleFrame(withMeta) {
		return framedData
	}
	*nextMetaAt = time.Now().Add(ntcp2NextMetaInterval())
	return withMeta
}

// frameMessage frames an I2NP message for transmission using NTCP2 block format.
// Returns the framed data or sets an error and returns nil.
//
// ntcp2.rst:1626-1628 forbids fragmenting an I2NP message across blocks or
// across ChaChaPoly frames: "I2NP messages may not be fragmented across blocks
// or across ChaChaPoly frames." A message whose block does not fit in a single
// data-phase frame must therefore never be put on the wire split up. The
// outbound write path in go-noise (Conn.writeFramed, conn_framing.go:439-478)
// splits any oversized payload across frames transparently, so the session
// refuses to send an oversized message instead: the message is dropped and
// counted, and the send path continues with the next queued message.
func (s *NTCP2Session) frameMessage(msg i2np.Message) ([]byte, error) {
	framedData, err := FrameI2NPMessageAsBlock(msg)
	if err != nil {
		s.setError(WrapNTCP2Error(err, "framing message"))
		return nil, err
	}

	if !s.fitsInSingleFrame(framedData) {
		s.logOversizedMessageDrop(msg, len(framedData))
		s.SessionCore.RecordDroppedMessage()
		return nil, nil
	}

	return framedData, nil
}

// Outbound single-frame sizing constants. go-noise's Conn.writeFramed
// (conn_framing.go:439-478) silently splits any payload larger than one
// frame across multiple ChaChaPoly frames, which ntcp2.rst:1626-1628 forbids
// for I2NP messages; the session therefore sizes its own writes so nothing it
// queues needs splitting.
//
// The per-frame plaintext ceiling is the configured maximum frame size minus
// the 16-byte Poly1305 tag. The transport raises go-noise's default to the
// largest frame the wire format can carry (see [applyNTCP2FrameSettings]), so
// a message that fits the spec's own block limit is actually delivered rather
// than dropped. The outbound AEAD padding modifier then appends up to
// MaxPaddingSize + 3 block-header bytes to the frame, so that headroom is
// reserved too — otherwise the padding itself would push the frame over the
// limit and re-introduce the split.
const (
	ntcp2SpecMaxFrameSize   = 65535 // ntcp2.rst:1444 maximum ChaChaPoly frame
	ntcp2Poly1305Overhead   = 16    // go-noise ntcp2.Poly1305Overhead
	ntcp2DefaultMaxPadding  = 64    // go-noise ntcp2.DefaultMaxPaddingSize
	ntcp2MaxTotalBlockSize  = 65519 // ntcp2.rst:1446 maximum total block size
	ntcp2PaddingOverhead    = blockHeaderSize + ntcp2DefaultMaxPadding
	ntcp2WriteFramedCeiling = ntcp2SpecMaxFrameSize - ntcp2Poly1305Overhead
)

// maxOutboundFramePlaintext returns the largest block payload (DateTime and
// I2NP blocks included) the session may hand to conn.Write in one frame
// without go-noise fragmenting it across ChaChaPoly frames.
//
// Two ceilings bound it, and the smaller wins:
//
//   - writeFramed splits at its configured maximum frame size minus the
//     authentication tag, which [applyNTCP2FrameSettings] sets to the spec
//     maximum, so 65535 - 16 = 65519;
//   - the padding modifier appends a Padding block after the payload, so the
//     payload must leave that much headroom or the padded frame would exceed
//     the split point and be fragmented anyway.
//
// The result is the same value i2pd uses for its own outbound frames
// (NTCP2_UNENCRYPTED_FRAME_MAX_SIZE), so a message go-i2p is willing to send is
// one a peer is willing to receive.
func maxOutboundFramePlaintext() int {
	maxPlaintext := ntcp2WriteFramedCeiling - ntcp2PaddingOverhead
	if maxPlaintext > ntcp2MaxTotalBlockSize {
		maxPlaintext = ntcp2MaxTotalBlockSize
	}
	return maxPlaintext
}

// applyNTCP2FrameSettings raises a connection config's outbound frame size to
// the largest frame the wire format carries.
//
// go-noise defaults MaxFrameSize to 16 KiB, which is well under the spec's
// 65535-byte frame (ntcp2.rst:1444). Since the session refuses to fragment an
// I2NP message across frames, that default silently caps every outbound message
// at roughly 16 KiB: anything larger is dropped and the peer never receives it,
// with no error to the caller. Raising it to the spec maximum makes the drop
// path match what the spec actually forbids — messages too large for a frame at
// all — rather than messages merely larger than an implementation default.
//
// Padding is left at go-noise's defaults (0-64 bytes) so the headroom reserved
// in [maxOutboundFramePlaintext] stays accurate.
func applyNTCP2FrameSettings(config *ntcp2.Config) *ntcp2.Config {
	if config == nil {
		return nil
	}
	return config.WithFrameSettings(ntcp2SpecMaxFrameSize, true, 0, ntcp2DefaultMaxPadding)
}

// fitsInSingleFrame reports whether payload fits in one outbound data-phase
// frame after the mandatory AEAD padding headroom is applied.
func (s *NTCP2Session) fitsInSingleFrame(payload []byte) bool {
	return len(payload) <= maxOutboundFramePlaintext()
}

// logOversizedMessageDrop records why an outbound message was refused.
func (s *NTCP2Session) logOversizedMessageDrop(msg i2np.Message, framedSize int) {
	s.Logger().WithFields(map[string]interface{}{
		"message_type":   msg.Type(),
		"framed_size":    framedSize,
		"max_frame_size": maxOutboundFramePlaintext(),
	}).Warn("Outbound NTCP2 message exceeds one ChaChaPoly frame; dropping rather than fragmenting (ntcp2.rst:1626-1628)")
}

// writeFramedData writes framed data to the connection.
// Returns false if an error occurred, true if write succeeded.
func (s *NTCP2Session) writeFramedData(framedData []byte) bool {
	// Check if conn has been detached.
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn == nil {
		return false
	}
	bytesWritten, err := conn.Write(framedData)
	if err != nil {
		s.Logger().WithError(err).WithField("bytes_written", bytesWritten).Error("Failed to write message to connection")
		s.setError(WrapNTCP2Error(err, "writing message"))
		return false
	}
	// Track outbound bandwidth
	s.AddToBytesSent(uint64(bytesWritten))
	s.markSendActivity()
	s.Logger().WithField("bytes_written", bytesWritten).Debug("Message written successfully")

	// Track message count for the replacement threshold
	s.checkRekey(s.rekeyState.recordSent())

	return true
}

// ntcp2ReadDeadline is the maximum time to wait for a message from a peer
// before checking if the session should stop. This prevents goroutine leaks
// when a peer goes silent without closing the connection.
const ntcp2ReadDeadline = 5 * time.Minute

// ntcp2TerminationWriteTimeout bounds the best-effort Termination block written
// during teardown. A close must never wait on a peer that has stopped reading:
// the socket, the transport registry entry and the session slot are only
// released once this write returns.
const ntcp2TerminationWriteTimeout = 2 * time.Second

// receiveWorker handles receiving I2NP messages from the NTCP2 connection.
func (s *NTCP2Session) receiveWorker() {
	defer s.WaitGroup().Done()
	s.Logger().Debug("Receive worker started")
	defer s.Logger().Debug("Receive worker stopped")

	unframer := s.createBlockUnframer()

	for {
		if s.shouldStopReceiving() {
			return
		}

		if !s.processNextInboundMessageFromBlocks(unframer) {
			return
		}
	}
}

// processNextInboundMessageFromBlocks sets a read deadline, reads the next message, and queues it.
// Returns false if the receive loop should exit due to a fatal error or queuing failure.
func (s *NTCP2Session) processNextInboundMessageFromBlocks(unframer *BlockUnframer) bool {
	// Check if conn has been detached.
	// This prevents nil dereference when DetachConn() is called before workers exit.
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn == nil {
		return false
	}
	if err := conn.SetReadDeadline(time.Now().Add(ntcp2ReadDeadline)); err != nil {
		s.Logger().WithError(err).Error("Failed to set read deadline")
		s.setError(WrapNTCP2Error(err, "setting read deadline"))
		return false
	}

	msg, err := s.readNextMessageFromBlocks(unframer)
	if err != nil {
		return s.handleReadResult(err)
	}

	if !s.allowInboundMessage(msg) {
		return false
	}

	return s.queueReceivedMessage(msg)
}

func (s *NTCP2Session) allowInboundMessage(msg i2np.Message) bool {
	if s.InboundLimiter().Allow() {
		return true
	}
	s.Logger().WithField("message_type", msg.Type()).Warn("Inbound I2NP rate limit exceeded, closing session")
	// setError schedules the teardown itself; no separate Close here.
	s.setError(oops.Errorf("inbound I2NP rate limit exceeded"))
	return false
}

// handleReadResult evaluates a read error and returns true if the loop should continue
// (e.g. on a read-deadline timeout) or false if the error is fatal.
func (s *NTCP2Session) handleReadResult(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		s.Logger().Debug("Read deadline expired, checking session state")
		return true
	}

	// W5: a data-phase frame that violates the spec's block ordering rules
	// (ntcp2.rst:1455-1469, :1675, :1742) is fatal. setError is the single
	// teardown funnel, and it maps the violation to its own reason code
	// (8 = Padding Violation, 10 = Payload Format Error) so the peer learns why.
	var violation *BlockOrderViolation
	if errors.As(err, &violation) {
		s.Logger().WithFields(map[string]interface{}{
			"rule":   violation.Rule,
			"reason": violation.Reason,
			"detail": violation.Detail,
		}).Warn("NTCP2 data-phase block ordering violation, closing session")
		s.setError(WrapNTCP2Error(violation, "invalid NTCP2 block ordering"))
		return false
	}

	s.handleReceiveError(err)
	return false
}

// createBlockUnframer creates and returns a new block-based unframer for this session's connection.
func (s *NTCP2Session) createBlockUnframer() *BlockUnframer {
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	unframer := NewBlockUnframer(conn)
	// Set optional callback for non-I2NP blocks (DateTime, Options, etc.)
	unframer.BlockCallback = s.handleNonI2NPBlock
	return unframer
}

// handleNonI2NPBlock processes non-I2NP blocks received during the data phase.
func (s *NTCP2Session) handleNonI2NPBlock(block Block) {
	s.markRecvActivity()
	switch block.Type {
	case BlockTypeDateTime:
		if ts, err := ParseDateTimeBlock(block.Data); err == nil {
			s.Logger().WithField("peer_time", ts).Debug("Received DateTime block from peer")
		}
	case BlockTypeOptions:
		s.handleOptionsBlock(block.Data)
	case BlockTypePadding:
		// Padding is ignored per spec
	case BlockTypeRouterInfo:
		s.handleRouterInfoBlock(block.Data)
	case BlockTypeTermination:
		reason := byte(0)
		if len(block.Data) >= terminationBlockPayloadSize {
			reason = block.Data[terminationBlockPayloadSize-1]
		}
		s.Logger().WithFields(map[string]interface{}{
			"at":          "(NTCP2Session) handleNonI2NPBlock",
			"reason_code": reason,
			"reason":      TerminationReasonString(reason),
		}).Warn("Received Termination block from peer, closing session")
		// Close in a goroutine to avoid deadlock: Close() calls wg.Wait(),
		// and this callback runs inside the receive worker goroutine.
		go func() { _ = s.Close() }()
	default:
		s.Logger().WithField("block_type", block.Type).Debug("Received unknown block type")
	}
}

// handleOptionsBlock parses and records an Options block received from the peer
// during the data phase (ntcp2.rst:1739 "Updated options may be sent during the
// data phase."). A block shorter than the spec's 12-byte minimum (:1515) is
// malformed: its contents are not applied and the event is logged, but the
// connection is kept, because the spec leaves the response to options/padding
// violations implementation-dependent (:1530 "These are guidelines, there
// is no enforcement"; :1773 "Router response on violation of negotiated padding
// is implementation-dependent").
func (s *NTCP2Session) handleOptionsBlock(data []byte) {
	opts, err := ParseOptionsBlock(data)
	if err != nil {
		s.Logger().WithError(err).Warn("Received malformed NTCP2 Options block, ignoring its contents")
		return
	}

	s.peerOptionsMu.Lock()
	snapshot := opts
	s.peerOptions = &snapshot
	s.peerOptionsMu.Unlock()

	s.Logger().WithFields(map[string]interface{}{
		"tmin_ratio":     RatioToFloat(opts.TransmitMinRatio),
		"tmax_ratio":     RatioToFloat(opts.TransmitMaxRatio),
		"rmin_ratio":     RatioToFloat(opts.ReceiveMinRatio),
		"rmax_ratio":     RatioToFloat(opts.ReceiveMaxRatio),
		"tdmy_bytes_sec": opts.TransmitDummy,
		"rdmy_bytes_sec": opts.ReceiveDummy,
		"tdelay_ms":      opts.TransmitDelay,
		"rdelay_ms":      opts.ReceiveDelay,
		"extra_bytes":    len(opts.Extra),
	}).Debug("Recorded peer NTCP2 options")
}

// PeerOptions returns the most recent valid Options block received from the
// peer, or nil if none has been received. The peer's transmit limits
// (TransmitMinRatio/TransmitMaxRatio) describe the padding it will send us; its
// receive limits describe what it would like us to send.
//
// Note that go-noise trunk exposes no accessor for the live padding modifier,
// so these values cannot yet be pushed into the outbound padding path; they are
// recorded for observability and for the transport layer to act on.
func (s *NTCP2Session) PeerOptions() *OptionsData {
	s.peerOptionsMu.Lock()
	defer s.peerOptionsMu.Unlock()
	if s.peerOptions == nil {
		return nil
	}
	cp := *s.peerOptions
	return &cp
}

// SetRouterInfoCallback sets a callback for RouterInfo blocks received from the
// peer during the data phase. The callback receives the raw RouterInfo bytes and
// the block's flood-request flag.
func (s *NTCP2Session) SetRouterInfoCallback(cb func(riBytes []byte, floodRequested bool)) {
	s.routerInfoMu.Lock()
	s.routerInfoCallback = cb
	s.routerInfoMu.Unlock()
}

// handleRouterInfoBlock parses a data-phase RouterInfo block and hands the raw
// RouterInfo bytes to the registered callback for validation and storage.
//
// Per ntcp2.rst §"RouterInfo Block", the block data is a 1-byte flag followed by
// the RouterInfo: bit 0 is "0 for local store, 1 for flood request" and bits 7-1
// are unused. The spec is explicit that "The Router Info is NOT compressed with
// gzip (unlike in a DatabaseStore Message, where it is)", so bit 0 must never be
// treated as a compression indicator.
//
// The spec also requires the receiver to validate the Router Hash matches the
// peer, validate the signature, validate a more-recent timestamp, store it in the
// local netdb as a local DatabaseStore, and flood it when bit 0 is set and this
// router is a floodfill. Those steps need the transport's peer identity and netdb
// wiring, so they live in the transport callback rather than here.
func (s *NTCP2Session) handleRouterInfoBlock(data []byte) {
	if len(data) < 2 {
		s.Logger().Warn("RouterInfo block too short")
		return
	}
	flag := data[0]
	riData := data[1:]
	floodRequested := flag&0x01 != 0

	s.routerInfoMu.Lock()
	cb := s.routerInfoCallback
	s.routerInfoMu.Unlock()

	if cb != nil {
		cb(riData, floodRequested)
	} else {
		s.Logger().Debug("Received RouterInfo block but no callback registered")
	}
}

// shouldStopReceiving checks if the session context is done and receiving should stop.
func (s *NTCP2Session) shouldStopReceiving() bool {
	select {
	case <-s.GetContext().Done():
		return true
	default:
		return false
	}
}

// readNextMessageFromBlocks reads the next I2NP message from the block unframer and tracks bytes received.
func (s *NTCP2Session) readNextMessageFromBlocks(unframer *BlockUnframer) (i2np.Message, error) {
	msg, err := unframer.ReadNextMessage()
	if err == nil {
		// Track bytes received atomically
		bytesRead := unframer.BytesRead()
		s.AddToBytesReceived(uint64(bytesRead))
		s.markRecvActivity()
		s.Logger().WithField("bytes_read", bytesRead).Debug("Message read successfully")
	}
	return msg, err
}

// handleReceiveError handles errors that occur during message receiving.
// P2.2: EOF, timeouts, and connection resets are normal peer-churn events;
// log at Warn instead of Error to avoid flooding logs.
func (s *NTCP2Session) handleReceiveError(err error) {
	switch {
	case errors.Is(err, io.EOF):
		recordSessionEOFClose()
		s.Logger().WithError(err).Warn("Connection closed by remote peer (EOF)")
	case errors.Is(err, net.ErrClosed):
		s.Logger().WithError(err).Warn("Read on closed connection")
	case isTimeoutOrReset(err):
		recordSessionTimeoutOrReset()
		s.Logger().WithError(err).Warn("Connection lost (timeout or reset)")
	default:
		s.Logger().WithError(err).Error("Failed to read message from connection")
	}
	s.setError(WrapNTCP2Error(err, "reading message"))
}

// isTimeoutOrReset returns true for network errors that indicate normal
// connection churn: read timeouts and connection resets by peer.
func isTimeoutOrReset(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Err.Error() == "connection reset by peer" ||
			opErr.Err.Error() == "read: connection reset by peer"
	}
	return false
}

// queueReceivedMessage attempts to queue a received message to the receive channel.
// Returns false if the session context is done, true if message was queued successfully.
// Uses a non-blocking attempt first to avoid stalling the receive worker when the
// channel is full, falling back to a short timeout before dropping the message.
func (s *NTCP2Session) queueReceivedMessage(msg i2np.Message) bool {
	s.Logger().WithField("message_type", msg.Type()).Debug("Received message, queueing to receive channel")

	// Try non-blocking first
	select {
	case s.RecvChan() <- msg:
		s.Logger().Debug("Message queued to receive channel successfully")
		s.checkRekey(s.rekeyState.recordReceived())
		return true
	case <-s.GetContext().Done():
		s.Logger().Warn("Cannot queue received message - session is closed")
		return false
	default:
	}

	return s.queueWithBackpressure(msg)
}

// queueWithBackpressure waits briefly for space in the receive channel before dropping
// the message to avoid stalling the receive worker. Returns true even on drop so
// the receiveWorker continues processing subsequent messages.
func (s *NTCP2Session) queueWithBackpressure(msg i2np.Message) bool {
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()

	select {
	case s.RecvChan() <- msg:
		s.Logger().Debug("Message queued to receive channel successfully (after backpressure)")
		s.checkRekey(s.rekeyState.recordReceived())
		return true
	case <-s.GetContext().Done():
		s.Logger().Warn("Cannot queue received message - session is closed")
		return false
	case <-timer.C:
		s.recordAndLogDroppedMessage(msg)
		return true // Continue receiving — don't kill the worker for backpressure
	}
}

// recordAndLogDroppedMessage increments the dropped message counter and logs the event.
func (s *NTCP2Session) recordAndLogDroppedMessage(msg i2np.Message) {
	recordSessionRecvBackpressure()
	s.RecordDroppedMessage()
	dropped := s.DroppedMessages()
	s.Logger().WithFields(map[string]interface{}{
		"message_type":  msg.Type(),
		"total_dropped": dropped,
		"recv_chan_cap": cap(s.RecvChan()),
	}).Warn("Dropping received message - receive channel full (backpressure)")
}

// checkRekey enforces the NTCP2 key/nonce lifetime bound. NTCP2 has no
// in-band mid-session rekey (see RekeyThreshold doc), so once a session has
// carried RekeyThreshold messages it is gracefully closed and the transport
// re-establishes a fresh handshake on the next send.
//
// The teardown is scheduled asynchronously: this runs inside the send/receive
// workers, and CloseWithReason joins the worker WaitGroup, so closing inline
// would deadlock the calling worker. The one-shot trigger guarantees exactly
// one replacement even if both workers cross the threshold at once.
func (s *NTCP2Session) checkRekey(totalMessages uint64) {
	if totalMessages < RekeyThreshold {
		return
	}
	if !s.rekeyState.tryTriggerReplacement() {
		// Another worker already claimed the replacement; do nothing.
		return
	}
	s.Logger().WithFields(map[string]interface{}{
		"total_messages": totalMessages,
		"threshold":      RekeyThreshold,
	}).Info("Rekey threshold reached, replacing NTCP2 session with a fresh handshake")
	// Normal close sends a termination block so the peer can re-dial; the
	// cleanup callback removes this session from the transport map.
	go func() { _ = s.CloseWithReason(TerminationNormalClose) }()
}

// GetTrafficStats returns per-session traffic statistics:
// totalMessages is the count of messages sent plus received over the session,
// and replacements is the number of threshold-triggered session replacements
// (0 or 1 for a live session). This replaces the former GetRekeyStats, which
// reported in-band rekeys that NTCP2 does not support.
func (s *NTCP2Session) GetTrafficStats() (totalMessages, replacements uint64) {
	return s.rekeyState.totalMessages(), s.rekeyState.getReplacementCount()
}

// getError returns the last error recorded by setError, if any. Safe for
// concurrent use with setError.
func (s *NTCP2Session) getError() error {
	s.errorMu.Lock()
	defer s.errorMu.Unlock()
	return s.lastError
}

// IsAlive reports whether this session can still carry traffic.
//
// It is nil-safe and core-safe so a session map can gate lookups on liveness
// without panicking on a zero-value or nil placeholder. A session that has
// lost its context is dead even when its socket has not been closed yet: the
// workers are gone, nothing will ever be read from or written to it again, and
// keeping it registered hides the peer's departure from the router, which then
// never redials (finding 006).
func (s *NTCP2Session) IsAlive() bool {
	if s == nil || s.SessionCore == nil {
		return false
	}
	return s.SessionCore.IsAlive()
}

// CloseRequested reports whether the session's teardown has started, either
// through an explicit Close or through the automatic teardown an error
// triggers. Used by idle maintenance to spot sessions that were cancelled
// without ever being closed.
func (s *NTCP2Session) CloseRequested() bool {
	if s == nil {
		return false
	}
	return s.closeRequested.Load()
}

// setError records the session's terminal error (once), cancels the context
// and schedules the full teardown.
//
// Cancelling alone is what made finding 006 permanent: the socket stayed open,
// the cleanup callback never ran, and the session stayed in the transport
// registry and the router's activeSessions, so the router kept routing to a
// dead link and never redialled. The teardown therefore has to be driven from
// here, the single funnel every fatal read/write error passes through.
//
// The cleanup callback is not called directly — Close() runs it after joining
// the workers, which prevents the transport from creating a new session to the
// same peer while old workers still run. Close is scheduled on its own
// goroutine because it joins the worker WaitGroup and setError is called from
// inside a worker.
func (s *NTCP2Session) setError(err error) {
	s.errorMu.Lock()
	if s.lastError != nil {
		s.errorMu.Unlock()
		return
	}
	s.lastError = err

	// EOF indicates the remote peer closed the connection — this is normal
	// peer churn, not an error condition. Log at Warn to avoid flooding
	// the error log with non-actionable entries.
	switch {
	case errors.Is(err, io.EOF):
		s.Logger().WithError(err).Warn("Session closed by remote peer")
	case isTimeoutOrReset(err):
		s.Logger().WithError(err).Warn("Session closed due to timeout or reset")
	default:
		s.Logger().WithError(err).Error("Session error")
	}
	s.Cancel()
	s.errorMu.Unlock()

	reason := terminationReasonForReadError(err)
	go func() {
		if closeErr := s.CloseWithReason(reason); closeErr != nil {
			s.Logger().WithError(closeErr).WithField("reason", TerminationReasonString(reason)).
				Debug("NTCP2 session close after error returned an error")
		}
	}()
}

// terminationReasonForReadError maps a fatal read/write error to the NTCP2
// Termination block reason code the session should report, per the spec's
// reason list (ntcp2.rst "Termination block").
//
// A block-ordering violation carries its own code. Cipher-level failures map to
// the AEAD-failure reason so CloseWithReason skips the termination block — the
// cipher state is no longer trustworthy, and go-noise has already performed the
// spec's AEAD teardown (probing resistance plus its own termination frame) on
// the connection before handing us the error. Everything else is reported as a
// normal close; the write is best-effort and simply fails on a dead socket.
func terminationReasonForReadError(err error) byte {
	// Frame-level failures carry the reason the spec prescribes for them:
	// *BlockOrderViolation for a frame that decodes but is ordered wrongly
	// (8 or 10), *BlockParseError for a frame that does not decode at all (10).
	var terminator interface{ TerminationReason() byte }
	if errors.As(err, &terminator) {
		return terminator.TerminationReason()
	}
	if isCipherLevelError(err) {
		return TerminationAEADFailure
	}
	return TerminationNormalClose
}

// cipherLevelErrorCodes are the go-noise error codes that mean the frame could
// not be authenticated or de-framed, i.e. the cipher/SipHash state of the
// connection is no longer usable. go-noise marks its Conn broken and performs
// the spec's AEAD error handling for all of them.
var cipherLevelErrorCodes = [...]string{
	"DECRYPT_FAILED",
	"READ_LENGTH_FAILED",
	"FRAME_TOO_SMALL",
	"FRAME_TOO_LARGE",
	"CONNECTION_BROKEN",
	"NONCE_EXHAUSTED",
	"ENCRYPT_FAILED",
}

// isCipherLevelError reports whether err carries one of go-noise's cipher or
// framing failure codes. Codes are read from the deepest oops layer, which is
// where WrapNTCP2Error leaves the original.
func isCipherLevelError(err error) bool {
	oopsErr, ok := oops.AsOops(err)
	if !ok {
		return false
	}
	code, ok := oopsErr.Code().(string)
	if !ok {
		return false
	}
	for _, c := range cipherLevelErrorCodes {
		if code == c {
			return true
		}
	}
	return false
}
