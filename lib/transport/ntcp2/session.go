package ntcp2

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NTCP2Session represents an active NTCP2 connection session with a remote peer, managing message queues, bandwidth tracking, and rekeying state.
type NTCP2Session struct {
	// Shared session core fields: queues, bandwidth tracking, lifecycle, and callbacks.
	// This embeds *SessionCore, so callers can call QueueSendI2NP, ReadNextI2NP, etc. directly.
	*transport.SessionCore

	// Underlying connection (uses net.Conn interface per guidelines)
	conn   net.Conn   // Will be *ntcp2.NTCP2Conn internally
	connMu sync.Mutex // protects conn field (SM-2 fix)

	// Rekeying state — tracks message counts for periodic rekeying
	rekeyState *rekeyState

	// Error handling
	lastError error
	errorOnce sync.Once

	// RouterInfo callback (called when a RouterInfo block is received from peer)
	routerInfoMu       sync.Mutex
	routerInfoCallback func([]byte)
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
	sessionLogger.Info("Creating new NTCP2 session")

	session := &NTCP2Session{
		SessionCore: core,
		conn:        conn,
		rekeyState:  newRekeyState(),
		lastError:   nil,
		errorOnce:   sync.Once{},
	}

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
	s.Logger().Info("NTCP2 session workers started")
}

// ReadNextI2NP blocking reads the next fully received I2NP message from this session.
// If a critical error occurred during receive processing, it is returned instead
// of waiting for more messages.
func (s *NTCP2Session) ReadNextI2NP() (i2np.Message, error) {
	select {
	case msg := <-s.RecvChan():
		return msg, nil
	case <-s.GetContext().Done():
		if s.lastError != nil {
			return nil, s.lastError
		}
		return nil, ErrSessionClosed
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
//
// For all other reasons, an encrypted termination block is sent through the
// NTCP2 connection's Noise cipher state (via conn.Write), which ensures it is
// encrypted and has a SipHash-obfuscated length prefix like any other data-phase
// frame. No plaintext termination blocks are ever sent.
//
// Spec reference: https://geti2p.net/spec/ntcp2#termination
func (s *NTCP2Session) CloseWithReason(reason byte) error {
	var err error
	s.CloseOnce().Do(func() {
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
			s.sendEncryptedTermination(reason)
		}

		s.Cancel()
		s.connMu.Lock()
		conn := s.conn
		s.connMu.Unlock()
		if conn != nil {
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

// DetachConn clears the session's reference to the underlying connection,
// preventing Close() from closing the socket. This is used when a session
// loses a promotion race — the winner owns the socket, so the loser must
// not close it. Workers will still stop cleanly when Close() cancels the
// session context (SM-2 fix).
func (s *NTCP2Session) DetachConn() {
	s.connMu.Lock()
	s.conn = nil
	s.connMu.Unlock()
}

// sendEncryptedTermination sends an encrypted termination block through the
// NTCP2 connection's Noise cipher state. The block is encrypted and framed
// by conn.Write, which applies AEAD encryption and SipHash length obfuscation,
// ensuring no plaintext termination block ever appears on the wire.
//
// This is a best-effort operation: errors are logged but do not prevent the
// session from closing.
func (s *NTCP2Session) sendEncryptedTermination(reason byte) {
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn == nil {
		return
	}

	block := BuildTerminationBlock(reason)
	s.Logger().WithFields(map[string]interface{}{
		"reason":     TerminationReasonString(reason),
		"block_size": len(block),
	}).Debug("Sending encrypted termination block")

	if _, writeErr := conn.Write(block); writeErr != nil {
		s.Logger().WithError(writeErr).Debug("Failed to send encrypted termination block (best-effort)")
	} else {
		s.Logger().Debug("Encrypted termination block sent successfully")
	}
}

// drainSendQueue waits for the send queue to empty before close.
// This is called before canceling the session context so the sendWorker can
// still process queued messages.
func (s *NTCP2Session) drainSendQueue() {
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

	for {
		select {
		case msg := <-s.SendQueue():
			if !s.processSendQueueMessage(msg) {
				s.discardRemainingMessages()
				return
			}
		case <-s.GetContext().Done():
			s.discardRemainingMessages()
			return
		}
	}
}

// discardRemainingMessages drains and discards any messages left in the send queue
// after the worker decides to stop. This delegates to the SessionCore shared implementation.
func (s *NTCP2Session) discardRemainingMessages() {
	s.SessionCore.DiscardRemaining()
}

// processSendQueueMessage processes a single I2NP message from the send queue.
// Returns false if an error occurred and the worker should stop, true otherwise.
func (s *NTCP2Session) processSendQueueMessage(msg i2np.Message) bool {
	newSize := s.AddToSendQueueSize(-1)
	s.Logger().WithFields(map[string]interface{}{
		"message_type":       msg.Type(),
		"remaining_in_queue": newSize,
	}).Debug("Processing message from send queue")

	framedData, err := s.frameMessage(msg)
	if err != nil {
		return false
	}

	return s.writeFramedData(framedData)
}

// frameMessage frames an I2NP message for transmission using NTCP2 block format.
// Returns the framed data or sets an error and returns nil.
func (s *NTCP2Session) frameMessage(msg i2np.Message) ([]byte, error) {
	framedData, err := FrameI2NPMessageAsBlock(msg)
	if err != nil {
		s.setError(WrapNTCP2Error(err, "framing message"))
		return nil, err
	}
	return framedData, nil
}

// writeFramedData writes framed data to the connection.
// Returns false if an error occurred, true if write succeeded.
func (s *NTCP2Session) writeFramedData(framedData []byte) bool {
	// Check if conn has been detached (SM-2 fix: losing promotion race).
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
	s.Logger().WithField("bytes_written", bytesWritten).Debug("Message written successfully")

	// Track message count for rekeying
	s.checkRekey(s.rekeyState.recordSent())

	return true
}

// ntcp2ReadDeadline is the maximum time to wait for a message from a peer
// before checking if the session should stop. This prevents goroutine leaks
// when a peer goes silent without closing the connection.
const ntcp2ReadDeadline = 5 * time.Minute

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
	// Check if conn has been detached (SM-2 fix: losing promotion race).
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
	s.setError(oops.Errorf("inbound I2NP rate limit exceeded"))
	go func() { _ = s.Close() }()
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
	switch block.Type {
	case BlockTypeDateTime:
		if ts, err := ParseDateTimeBlock(block.Data); err == nil {
			s.Logger().WithField("peer_time", ts).Debug("Received DateTime block from peer")
		}
	case BlockTypeOptions:
		s.Logger().Debug("Received Options block from peer")
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

// SetRouterInfoCallback sets a callback for RouterInfo blocks received from the peer.
// The callback receives the raw (decompressed) RouterInfo bytes.
func (s *NTCP2Session) SetRouterInfoCallback(cb func([]byte)) {
	s.routerInfoMu.Lock()
	s.routerInfoCallback = cb
	s.routerInfoMu.Unlock()
}

// handleRouterInfoBlock parses a RouterInfo block, decompresses if needed,
// and passes the raw RouterInfo bytes to the registered callback.
func (s *NTCP2Session) handleRouterInfoBlock(data []byte) {
	if len(data) < 2 {
		s.Logger().Warn("RouterInfo block too short")
		return
	}
	flag := data[0]
	riData := data[1:]

	if flag&0x01 != 0 {
		decompressed, err := decompressGzip(riData)
		if err != nil {
			s.Logger().WithError(err).Warn("Failed to decompress RouterInfo block")
			return
		}
		riData = decompressed
	}

	s.routerInfoMu.Lock()
	cb := s.routerInfoCallback
	s.routerInfoMu.Unlock()

	if cb != nil {
		cb(riData)
	} else {
		s.Logger().Debug("Received RouterInfo block but no callback registered")
	}
}

// decompressGzip decompresses gzip-compressed data with a size limit to prevent gzip bomb DoS.
// Uses the centralized MaxDecompressedRouterInfoSize limit from lib/i2np.
func decompressGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, oops.Wrapf(err, "gzip reader")
	}
	defer func() { _ = r.Close() }()
	return io.ReadAll(io.LimitReader(r, i2np.MaxDecompressedRouterInfoSize))
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
		s.Logger().WithError(err).Warn("Connection closed by remote peer (EOF)")
	case errors.Is(err, net.ErrClosed):
		s.Logger().WithError(err).Warn("Read on closed connection")
	case isTimeoutOrReset(err):
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
	s.RecordDroppedMessage()
	dropped := s.DroppedMessages()
	s.Logger().WithFields(map[string]interface{}{
		"message_type":  msg.Type(),
		"total_dropped": dropped,
		"recv_chan_cap": cap(s.RecvChan()),
	}).Warn("Dropping received message - receive channel full (backpressure)")
}

// checkRekey checks if the session needs rekeying based on message count.
// If the threshold is reached, attempts to rekey the underlying connection.
func (s *NTCP2Session) checkRekey(totalMessages uint64) {
	if totalMessages >= RekeyThreshold {
		s.Logger().WithFields(map[string]interface{}{
			"total_messages": totalMessages,
			"threshold":      RekeyThreshold,
		}).Info("Rekey threshold reached, attempting session rekey")
		s.connMu.Lock()
		conn := s.conn
		s.connMu.Unlock()
		if attemptRekey(conn, s.rekeyState) {
			s.Logger().WithField("rekey_count", s.rekeyState.getRekeyCount()).Info("Session rekeyed successfully")
		} else {
			s.Logger().Debug("Session rekeying not available (connection does not implement Rekeyer)")
		}
	}
}

// GetRekeyStats returns rekeying statistics for this session:
// messagesSinceRekey is the count of messages since the last rekey (or session start),
// rekeyCount is the total number of successful rekeys performed.
func (s *NTCP2Session) GetRekeyStats() (messagesSinceRekey, rekeyCount uint64) {
	return s.rekeyState.totalMessages(), s.rekeyState.getRekeyCount()
}

// setError sets the last error (once) and cancels the session context.
// Cleanup callback is NOT called here — it is deferred to Close() which
// waits for workers to finish first, preventing the transport from
// creating a new session to the same peer while old workers still run.
func (s *NTCP2Session) setError(err error) {
	s.errorOnce.Do(func() {
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
	})
}
