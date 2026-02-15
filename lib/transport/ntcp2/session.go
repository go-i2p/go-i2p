package ntcp2

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/logger"
)

type NTCP2Session struct {
	// Underlying connection (uses net.Conn interface per guidelines)
	conn net.Conn // Will be *ntcp2.NTCP2Conn internally

	// I2NP message queues
	sendQueue chan i2np.I2NPMessage
	recvChan  chan i2np.I2NPMessage

	// Queue management
	sendQueueSize int32 // atomic counter

	// Bandwidth tracking (atomic counters for thread-safe access)
	// These track cumulative bytes since session start
	bytesSent     uint64 // atomic: total bytes sent over this session
	bytesReceived uint64 // atomic: total bytes received over this session

	// Backpressure tracking — counts messages dropped due to full receive channel
	droppedMessages uint64 // atomic: total messages dropped due to backpressure

	// Rekeying state — tracks message counts for periodic rekeying
	rekeyState *rekeyState

	// Error handling
	lastError error
	errorOnce sync.Once

	// Lifecycle management
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once

	// Background workers
	wg sync.WaitGroup

	// Cleanup callback (called when session closes)
	callbackMu      sync.Mutex // protects cleanupCallback field
	cleanupCallback func()
	cleanupOnce     sync.Once

	// Logging
	logger *logger.Entry
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
	sessionCtx, cancel := context.WithCancel(ctx)

	sessionLogger := logger.WithFields(map[string]interface{}{
		"component":   "ntcp2_session",
		"remote_addr": conn.RemoteAddr().String(),
	})
	sessionLogger.Info("Creating new NTCP2 session")

	session := &NTCP2Session{
		conn:          conn,
		sendQueue:     make(chan i2np.I2NPMessage, 256), // Buffered channel for send queue
		recvChan:      make(chan i2np.I2NPMessage, 256), // Buffered channel for receive messages
		ctx:           sessionCtx,
		cancel:        cancel,
		logger:        sessionLogger,
		rekeyState:    newRekeyState(),
		sendQueueSize: 0,
		lastError:     nil,
		errorOnce:     sync.Once{},
		closeOnce:     sync.Once{},
		wg:            sync.WaitGroup{},
	}

	sessionLogger.Info("NTCP2 session created (deferred workers)")
	return session
}

// StartWorkers launches the background send and receive goroutines.
// Must be called exactly once after the session is confirmed as the active session.
func (s *NTCP2Session) StartWorkers() {
	s.logger.Debug("Starting send and receive workers")
	s.wg.Add(2)
	go s.sendWorker()
	go s.receiveWorker()
	s.logger.Info("NTCP2 session workers started")
}

// QueueSendI2NP queues an I2NP message to be sent over the session.
// Returns an error if the session is closed or the send queue is full after a timeout.
func (s *NTCP2Session) QueueSendI2NP(msg i2np.I2NPMessage) error {
	s.logger.WithFields(map[string]interface{}{
		"message_type":       msg.Type(),
		"current_queue_size": atomic.LoadInt32(&s.sendQueueSize),
	}).Debug("Queueing I2NP message for send")

	// Increment queue size before channel send so SendQueueSize() always
	// reflects messages that are in-flight or queued. Decrement on failure.
	atomic.AddInt32(&s.sendQueueSize, 1)

	select {
	case s.sendQueue <- msg:
		s.logger.WithField("queue_size", atomic.LoadInt32(&s.sendQueueSize)).Debug("Message queued successfully")
		return nil
	case <-s.ctx.Done():
		atomic.AddInt32(&s.sendQueueSize, -1)
		s.logger.WithField("message_type", msg.Type()).Warn("Cannot queue message - session is closed")
		return fmt.Errorf("session closed, message dropped (type=%d)", msg.Type())
	case <-time.After(500 * time.Millisecond):
		atomic.AddInt32(&s.sendQueueSize, -1)
		s.logger.WithFields(map[string]interface{}{
			"message_type":       msg.Type(),
			"current_queue_size": atomic.LoadInt32(&s.sendQueueSize),
		}).Warn("Send queue full after timeout, dropping message")
		return fmt.Errorf("send queue full, message dropped (type=%d)", msg.Type())
	}
}

// SendQueueSize returns how many I2NP messages are not completely sent yet.
func (s *NTCP2Session) SendQueueSize() int {
	return int(atomic.LoadInt32(&s.sendQueueSize))
}

// GetBandwidthStats returns the total bytes sent and received by this session.
// Each counter is read atomically, but the pair is not a consistent snapshot:
// a concurrent send/receive between the two loads may cause slight skew.
// This is acceptable for monitoring and rate estimation; use a mutex-guarded
// snapshot if exact point-in-time consistency is ever required.
func (s *NTCP2Session) GetBandwidthStats() (bytesSent, bytesReceived uint64) {
	return atomic.LoadUint64(&s.bytesSent), atomic.LoadUint64(&s.bytesReceived)
}

// ReadNextI2NP blocking reads the next fully received I2NP message from this session.
func (s *NTCP2Session) ReadNextI2NP() (i2np.I2NPMessage, error) {
	select {
	case msg := <-s.recvChan:
		s.logger.WithField("message_type", msg.Type()).Debug("Read I2NP message from session")
		return msg, nil
	case <-s.ctx.Done():
		s.logger.Debug("ReadNextI2NP returning due to session close")
		if s.lastError != nil {
			return nil, s.lastError
		}
		return nil, ErrSessionClosed
	}
}

// sendQueueDrainTimeout is the maximum time to wait for queued messages to be
// sent before forcefully closing the session. This prevents message loss during
// graceful shutdown while avoiding indefinite hangs.
const sendQueueDrainTimeout = 2 * time.Second

// Close closes the session cleanly.
// It first waits briefly for the send queue to drain (up to sendQueueDrainTimeout)
// before canceling the context and closing the connection. This gives queued
// messages a chance to be transmitted rather than being silently dropped.
func (s *NTCP2Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.logger.Info("Closing NTCP2 session")

		// Wait for send queue to drain before canceling context.
		// The sendWorker is still running at this point, so queued messages
		// can still be transmitted.
		s.drainSendQueue()

		s.cancel()
		if s.conn != nil {
			err = s.conn.Close()
			if err != nil {
				s.logger.WithError(err).Warn("Error closing connection")
			}
		}
		s.logger.Debug("Waiting for session workers to complete")
		s.wg.Wait()

		// Call cleanup callback to remove session from transport map
		s.callCleanupCallback()
		s.logger.Info("NTCP2 session closed successfully")
	})
	return err
}

// drainSendQueue waits for the send queue to empty or the drain timeout to expire.
// This is called before canceling the session context so the sendWorker can
// still process queued messages.
func (s *NTCP2Session) drainSendQueue() {
	queueSize := atomic.LoadInt32(&s.sendQueueSize)
	if queueSize == 0 {
		return
	}

	s.logger.WithField("queue_size", queueSize).Debug("Draining send queue before close")

	deadline := time.NewTimer(sendQueueDrainTimeout)
	defer deadline.Stop()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline.C:
			remaining := atomic.LoadInt32(&s.sendQueueSize)
			if remaining > 0 {
				s.logger.WithField("remaining", remaining).Warn("Send queue drain timeout, dropping remaining messages")
			}
			return
		case <-ticker.C:
			if atomic.LoadInt32(&s.sendQueueSize) == 0 {
				s.logger.Debug("Send queue drained successfully")
				return
			}
		}
	}
}

// SetCleanupCallback sets a callback function that will be called when the session closes.
// Thread-safe: protected by callbackMu to prevent data race with callCleanupCallback.
func (s *NTCP2Session) SetCleanupCallback(callback func()) {
	s.callbackMu.Lock()
	s.cleanupCallback = callback
	s.callbackMu.Unlock()
}

// callCleanupCallback calls the cleanup callback (once) if it's set.
// Thread-safe: reads cleanupCallback under callbackMu.
func (s *NTCP2Session) callCleanupCallback() {
	s.cleanupOnce.Do(func() {
		s.callbackMu.Lock()
		cb := s.cleanupCallback
		s.callbackMu.Unlock()
		if cb != nil {
			cb()
		}
	})
}

// sendWorker handles sending I2NP messages over the NTCP2 connection.
func (s *NTCP2Session) sendWorker() {
	defer s.wg.Done()
	s.logger.Debug("Send worker started")
	defer s.logger.Debug("Send worker stopped")

	for {
		select {
		case msg := <-s.sendQueue:
			if !s.processSendQueueMessage(msg) {
				s.discardRemainingMessages()
				return
			}
		case <-s.ctx.Done():
			s.discardRemainingMessages()
			return
		}
	}
}

// discardRemainingMessages drains and discards any messages left in the send queue
// after the worker decides to stop. This ensures sendQueueSize reaches zero so
// drainSendQueue does not spin waiting for a defunct worker.
func (s *NTCP2Session) discardRemainingMessages() {
	for {
		select {
		case <-s.sendQueue:
			atomic.AddInt32(&s.sendQueueSize, -1)
		default:
			return
		}
	}
}

// processSendQueueMessage processes a single I2NP message from the send queue.
// Returns false if an error occurred and the worker should stop, true otherwise.
func (s *NTCP2Session) processSendQueueMessage(msg i2np.I2NPMessage) bool {
	newSize := atomic.AddInt32(&s.sendQueueSize, -1)
	s.logger.WithFields(map[string]interface{}{
		"message_type":       msg.Type(),
		"remaining_in_queue": newSize,
	}).Debug("Processing message from send queue")

	framedData, err := s.frameMessage(msg)
	if err != nil {
		return false
	}

	return s.writeFramedData(framedData)
}

// frameMessage frames an I2NP message for transmission.
// Returns the framed data or sets an error and returns nil.
func (s *NTCP2Session) frameMessage(msg i2np.I2NPMessage) ([]byte, error) {
	framedData, err := FrameI2NPMessage(msg)
	if err != nil {
		s.setError(WrapNTCP2Error(err, "framing message"))
		return nil, err
	}
	return framedData, nil
}

// writeFramedData writes framed data to the connection.
// Returns false if an error occurred, true if write succeeded.
func (s *NTCP2Session) writeFramedData(framedData []byte) bool {
	bytesWritten, err := s.conn.Write(framedData)
	if err != nil {
		s.logger.WithError(err).WithField("bytes_written", bytesWritten).Error("Failed to write message to connection")
		s.setError(WrapNTCP2Error(err, "writing message"))
		return false
	}
	// Track outbound bandwidth
	atomic.AddUint64(&s.bytesSent, uint64(bytesWritten))
	s.logger.WithField("bytes_written", bytesWritten).Debug("Message written successfully")

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
	defer s.wg.Done()
	s.logger.Debug("Receive worker started")
	defer s.logger.Debug("Receive worker stopped")

	unframer := s.createMessageUnframer()

	for {
		if s.shouldStopReceiving() {
			return
		}

		if !s.processNextInboundMessage(unframer) {
			return
		}
	}
}

// processNextInboundMessage sets a read deadline, reads the next message, and queues it.
// Returns false if the receive loop should exit due to a fatal error or queuing failure.
func (s *NTCP2Session) processNextInboundMessage(unframer *I2NPUnframer) bool {
	if err := s.conn.SetReadDeadline(time.Now().Add(ntcp2ReadDeadline)); err != nil {
		s.logger.WithError(err).Error("Failed to set read deadline")
		s.setError(WrapNTCP2Error(err, "setting read deadline"))
		return false
	}

	msg, err := s.readNextMessage(unframer)
	if err != nil {
		return s.handleReadResult(err)
	}

	return s.queueReceivedMessage(msg)
}

// handleReadResult evaluates a read error and returns true if the loop should continue
// (e.g. on a read-deadline timeout) or false if the error is fatal.
func (s *NTCP2Session) handleReadResult(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		s.logger.Debug("Read deadline expired, checking session state")
		return true
	}
	s.handleReceiveError(err)
	return false
}

// createMessageUnframer creates and returns a new I2NP unframer for this session's connection.
func (s *NTCP2Session) createMessageUnframer() *I2NPUnframer {
	return NewI2NPUnframer(s.conn)
}

// shouldStopReceiving checks if the session context is done and receiving should stop.
func (s *NTCP2Session) shouldStopReceiving() bool {
	select {
	case <-s.ctx.Done():
		return true
	default:
		return false
	}
}

// readNextMessage reads the next I2NP message from the unframer and tracks bytes received.
func (s *NTCP2Session) readNextMessage(unframer *I2NPUnframer) (i2np.I2NPMessage, error) {
	msg, err := unframer.ReadNextMessage()
	if err == nil {
		// Track bytes received atomically
		bytesRead := unframer.BytesRead()
		atomic.AddUint64(&s.bytesReceived, uint64(bytesRead))
		s.logger.WithField("bytes_read", bytesRead).Debug("Message read successfully")
	}
	return msg, err
}

// handleReceiveError handles errors that occur during message receiving.
func (s *NTCP2Session) handleReceiveError(err error) {
	s.logger.WithError(err).Error("Failed to read message from connection")
	s.setError(WrapNTCP2Error(err, "reading message"))
}

// queueReceivedMessage attempts to queue a received message to the receive channel.
// Returns false if the session context is done, true if message was queued successfully.
// Uses a non-blocking attempt first to avoid stalling the receive worker when the
// channel is full, falling back to a short timeout before dropping the message.
func (s *NTCP2Session) queueReceivedMessage(msg i2np.I2NPMessage) bool {
	s.logger.WithField("message_type", msg.Type()).Debug("Received message, queueing to receive channel")

	// Try non-blocking first
	select {
	case s.recvChan <- msg:
		s.logger.Debug("Message queued to receive channel successfully")
		s.checkRekey(s.rekeyState.recordReceived())
		return true
	case <-s.ctx.Done():
		s.logger.Warn("Cannot queue received message - session is closed")
		return false
	default:
	}

	return s.queueWithBackpressure(msg)
}

// queueWithBackpressure waits briefly for space in the receive channel before dropping
// the message to avoid stalling the receive worker. Returns true even on drop so
// the receiveWorker continues processing subsequent messages.
func (s *NTCP2Session) queueWithBackpressure(msg i2np.I2NPMessage) bool {
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()

	select {
	case s.recvChan <- msg:
		s.logger.Debug("Message queued to receive channel successfully (after backpressure)")
		s.checkRekey(s.rekeyState.recordReceived())
		return true
	case <-s.ctx.Done():
		s.logger.Warn("Cannot queue received message - session is closed")
		return false
	case <-timer.C:
		s.recordDroppedMessage(msg)
		return true // Continue receiving — don't kill the worker for backpressure
	}
}

// recordDroppedMessage increments the dropped message counter and logs the event.
func (s *NTCP2Session) recordDroppedMessage(msg i2np.I2NPMessage) {
	dropped := atomic.AddUint64(&s.droppedMessages, 1)
	s.logger.WithFields(map[string]interface{}{
		"message_type":  msg.Type(),
		"total_dropped": dropped,
		"recv_chan_cap": cap(s.recvChan),
	}).Warn("Dropping received message - receive channel full (backpressure)")
}

// checkRekey checks if the session needs rekeying based on message count.
// If the threshold is reached, attempts to rekey the underlying connection.
func (s *NTCP2Session) checkRekey(totalMessages uint64) {
	if totalMessages >= RekeyThreshold {
		s.logger.WithFields(map[string]interface{}{
			"total_messages": totalMessages,
			"threshold":      RekeyThreshold,
		}).Info("Rekey threshold reached, attempting session rekey")
		if attemptRekey(s.conn, s.rekeyState) {
			s.logger.WithField("rekey_count", s.rekeyState.getRekeyCount()).Info("Session rekeyed successfully")
		} else {
			s.logger.Debug("Session rekeying not available (connection does not implement Rekeyer)")
		}
	}
}

// GetRekeyStats returns rekeying statistics for this session:
// messagesSinceRekey is the count of messages since the last rekey (or session start),
// rekeyCount is the total number of successful rekeys performed.
func (s *NTCP2Session) GetRekeyStats() (messagesSinceRekey, rekeyCount uint64) {
	return s.rekeyState.totalMessages(), s.rekeyState.getRekeyCount()
}

// DroppedMessages returns the number of received messages that were dropped
// due to the receive channel being full (backpressure). A non-zero value
// indicates the consumer is not keeping up with inbound message rate.
func (s *NTCP2Session) DroppedMessages() uint64 {
	return atomic.LoadUint64(&s.droppedMessages)
}

// setError sets the last error (once) and cancels the session context.
// Cleanup callback is NOT called here — it is deferred to Close() which
// waits for workers to finish first, preventing the transport from
// creating a new session to the same peer while old workers still run.
func (s *NTCP2Session) setError(err error) {
	s.errorOnce.Do(func() {
		s.lastError = err
		s.logger.WithError(err).Error("Session error")
		s.cancel()
	})
}
