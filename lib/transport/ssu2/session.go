package ssu2

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/go-i2p/logger"
)

// retransmitTickInterval is how often the send worker checks for expired
// pending messages that need to be retransmitted.
const retransmitTickInterval = 50 * time.Millisecond

// ccPollInterval is the delay between congestion-window polling attempts
// when the window is full.
const ccPollInterval = 10 * time.Millisecond

// maxRetransmitBackoff caps the exponential back-off delay for retransmissions.
const maxRetransmitBackoff = 60 * time.Second

// maxRTTSample discards implausibly large RTT measurements from one-sided
// clock observations (e.g. when lastSendNano is stale).
const maxRTTSample = 30 * time.Second

// pendingI2NP tracks an I2NP message that has been written to the conn but
// has not yet been confirmed delivered (used for session-level retransmission).
type pendingI2NP struct {
	data     []byte
	sentAt   time.Time
	deadline time.Time // sentAt + rto; extended on each retransmit with back-off
	attempts int
}

// SSU2Session implements transport.TransportSession over an SSU2 connection.
type SSU2Session struct {
	conn *ssu2noise.SSU2Conn

	sendQueue     chan i2np.I2NPMessage
	recvChan      chan i2np.I2NPMessage
	sendQueueSize int32

	bytesSent       uint64
	bytesReceived   uint64
	droppedMessages uint64

	// Phase 5: Reliability & congestion control
	rttEstimator   *ssu2noise.RTTEstimator
	congestionCtrl *ssu2noise.CongestionController
	pendingMsgsMu  sync.Mutex
	pendingMsgs    map[uint64]*pendingI2NP
	pendingSeqNext uint64 // incremented atomically
	maxRetransmit  int
	lastSendNano   int64 // atomic unix-nano of most recent Write call

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	wg        sync.WaitGroup

	callbackMu      sync.Mutex
	cleanupCallback func()
	cleanupOnce     sync.Once

	logger *logger.Entry
}

// NewSSU2Session creates a new SSU2 session and starts background workers.
func NewSSU2Session(conn *ssu2noise.SSU2Conn, ctx context.Context, logger *logger.Entry) *SSU2Session {
	session := NewSSU2SessionDeferred(conn, ctx, logger)
	session.StartWorkers()
	return session
}

// NewSSU2SessionDeferred creates a new SSU2 session without starting workers.
// Call StartWorkers() after confirming the session will be used.
func NewSSU2SessionDeferred(conn *ssu2noise.SSU2Conn, ctx context.Context, logger *logger.Entry) *SSU2Session {
	sessionCtx, cancel := context.WithCancel(ctx)

	sessionLogger := logger.WithFields(map[string]interface{}{
		"component":   "ssu2_session",
		"remote_addr": conn.RemoteAddr().String(),
	})
	sessionLogger.Info("Creating new SSU2 session")

	rtt := ssu2noise.NewRTTEstimator()
	s := &SSU2Session{
		conn:           conn,
		sendQueue:      make(chan i2np.I2NPMessage, 256),
		recvChan:       make(chan i2np.I2NPMessage, 256),
		rttEstimator:   rtt,
		congestionCtrl: ssu2noise.NewCongestionController(rtt),
		pendingMsgs:    make(map[uint64]*pendingI2NP),
		maxRetransmit:  DefaultMaxRetransmissions,
		ctx:            sessionCtx,
		cancel:         cancel,
		logger:         sessionLogger,
	}
	s.wireDataHandlerCallbacks()
	return s
}

// wireDataHandlerCallbacks wires protocol-level callbacks from the go-noise
// DataHandler into the SSU2Session. Called once during session construction,
// before StartWorkers(), so callbacks are active from the first data packet.
func (s *SSU2Session) wireDataHandlerCallbacks() {
	s.conn.SetDataHandlerCallbacks(ssu2noise.DataHandlerCallbacks{
		// OnTermination: peer gracefully closed the session; cancel our context.
		OnTermination: func(reason uint8, _ []byte) {
			s.logger.WithField("termination_reason", reason).Warn("SSU2 session terminated by peer")
			s.cancel()
		},
		// OnDateTime: validate the peer's stated clock; large skews are a
		// sign of misconfiguration or a replay attack.
		OnDateTime: func(timestamp uint32) error {
			now := time.Now().Unix()
			delta := int64(timestamp) - now
			if delta < 0 {
				delta = -delta
			}
			if delta > 60 {
				s.logger.WithField("skew_seconds", delta).Warn("SSU2 clock skew out of tolerance, closing session")
				s.cancel()
				return fmt.Errorf("clock skew %ds exceeds 60s tolerance", delta)
			}
			return nil
		},
	})
}

// StartWorkers launches the background send and receive goroutines.
func (s *SSU2Session) StartWorkers() {
	s.wg.Add(2)
	go s.sendWorker()
	go s.receiveWorker()
	s.logger.Info("SSU2 session workers started")
}

// QueueSendI2NP queues an I2NP message to be sent over the session.
func (s *SSU2Session) QueueSendI2NP(msg i2np.I2NPMessage) error {
	atomic.AddInt32(&s.sendQueueSize, 1)

	select {
	case s.sendQueue <- msg:
		return nil
	case <-s.ctx.Done():
		atomic.AddInt32(&s.sendQueueSize, -1)
		return fmt.Errorf("session closed, message dropped (type=%d)", msg.Type())
	case <-time.After(500 * time.Millisecond):
		atomic.AddInt32(&s.sendQueueSize, -1)
		return fmt.Errorf("send queue full, message dropped (type=%d)", msg.Type())
	}
}

// SendQueueSize returns how many I2NP messages are not completely sent yet.
func (s *SSU2Session) SendQueueSize() int {
	return int(atomic.LoadInt32(&s.sendQueueSize))
}

// ReadNextI2NP blocking reads the next fully received I2NP message.
func (s *SSU2Session) ReadNextI2NP() (i2np.I2NPMessage, error) {
	select {
	case msg := <-s.recvChan:
		return msg, nil
	case <-s.ctx.Done():
		return nil, ErrSessionClosed
	}
}

// sendQueueDrainTimeout is the maximum time to wait for queued messages.
const sendQueueDrainTimeout = 2 * time.Second

// Close closes the session cleanly.
func (s *SSU2Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.logger.Info("Closing SSU2 session")
		s.drainSendQueue()
		s.cancel()
		if s.conn != nil {
			err = s.conn.Close()
		}
		s.wg.Wait()
		s.callCleanupCallback()
		s.logger.Info("SSU2 session closed")
	})
	return err
}

// SetCleanupCallback sets a callback invoked when the session closes.
func (s *SSU2Session) SetCleanupCallback(callback func()) {
	s.callbackMu.Lock()
	s.cleanupCallback = callback
	s.callbackMu.Unlock()
}

func (s *SSU2Session) callCleanupCallback() {
	s.cleanupOnce.Do(func() {
		s.callbackMu.Lock()
		cb := s.cleanupCallback
		s.callbackMu.Unlock()
		if cb != nil {
			cb()
		}
	})
}

// GetBandwidthStats returns total bytes sent and received by this session.
func (s *SSU2Session) GetBandwidthStats() (bytesSent, bytesReceived uint64) {
	return atomic.LoadUint64(&s.bytesSent), atomic.LoadUint64(&s.bytesReceived)
}

func (s *SSU2Session) drainSendQueue() {
	queueSize := atomic.LoadInt32(&s.sendQueueSize)
	if queueSize == 0 {
		return
	}

	deadline := time.NewTimer(sendQueueDrainTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline.C:
			return
		case <-ticker.C:
			if atomic.LoadInt32(&s.sendQueueSize) == 0 {
				return
			}
		}
	}
}

func (s *SSU2Session) sendWorker() {
	defer s.wg.Done()
	ticker := time.NewTicker(retransmitTickInterval)
	defer ticker.Stop()

	for {
		select {
		case msg := <-s.sendQueue:
			atomic.AddInt32(&s.sendQueueSize, -1)
			if err := s.sendWithCongestionControl(msg); err != nil {
				s.logger.WithError(err).Error("Failed to send message")
				s.discardRemainingMessages()
				return
			}
		case <-ticker.C:
			if s.handleRetransmissions() {
				s.logger.Warn("Max retransmissions exceeded, closing session")
				s.cancel()
				return
			}
		case <-s.ctx.Done():
			s.discardRemainingMessages()
			return
		}
	}
}

// sendWithCongestionControl serializes msg, waits for congestion-window room,
// then writes the bytes to the conn and records the pending delivery.
func (s *SSU2Session) sendWithCongestionControl(msg i2np.I2NPMessage) error {
	data, err := msg.MarshalBinary()
	if err != nil {
		return err
	}

	for !s.congestionCtrl.CanSend(len(data)) {
		select {
		case <-s.ctx.Done():
			return ErrSessionClosed
		case <-time.After(ccPollInterval):
		}
	}

	seq := s.trackPending(data)
	n, err := s.conn.Write(data)
	if err != nil {
		s.removePending(seq)
		s.congestionCtrl.OnPacketLoss()
		return err
	}
	atomic.StoreInt64(&s.lastSendNano, time.Now().UnixNano())
	atomic.AddUint64(&s.bytesSent, uint64(n))
	s.congestionCtrl.OnPacketSent(n)
	return nil
}

// trackPending stores an I2NP payload in the pending retransmission map and
// returns its sequence number.
func (s *SSU2Session) trackPending(data []byte) uint64 {
	seq := atomic.AddUint64(&s.pendingSeqNext, 1)
	rto := s.rttEstimator.GetRTO()
	now := time.Now()
	s.pendingMsgsMu.Lock()
	s.pendingMsgs[seq] = &pendingI2NP{
		data:     data,
		sentAt:   now,
		deadline: now.Add(rto),
	}
	s.pendingMsgsMu.Unlock()
	return seq
}

// removePending deletes a pending message from the map.
func (s *SSU2Session) removePending(seq uint64) {
	s.pendingMsgsMu.Lock()
	delete(s.pendingMsgs, seq)
	s.pendingMsgsMu.Unlock()
}

// handleRetransmissions checks all pending I2NP messages and retransmits any
// that have exceeded their RTO deadline.  Returns true if the session should
// be closed (max retransmissions exceeded for at least one message).
func (s *SSU2Session) handleRetransmissions() (shouldClose bool) {
	now := time.Now()
	var toDelete []uint64
	var hadLoss bool

	s.pendingMsgsMu.Lock()
	for seq, p := range s.pendingMsgs {
		if now.Before(p.deadline) {
			continue
		}
		if p.attempts >= s.maxRetransmit {
			toDelete = append(toDelete, seq)
			hadLoss = true
			shouldClose = true
			continue
		}
		if n, err := s.conn.Write(p.data); err != nil {
			toDelete = append(toDelete, seq)
			hadLoss = true
		} else {
			atomic.AddUint64(&s.bytesSent, uint64(n))
			p.attempts++
			backoff := s.rttEstimator.GetRTO() * (1 << uint(p.attempts))
			if backoff > maxRetransmitBackoff {
				backoff = maxRetransmitBackoff
			}
			p.deadline = now.Add(backoff)
			s.pendingMsgs[seq] = p
		}
	}
	for _, seq := range toDelete {
		delete(s.pendingMsgs, seq)
	}
	s.pendingMsgsMu.Unlock()

	if hadLoss {
		s.congestionCtrl.OnRetransmissionTimeout()
	}
	return shouldClose
}

// ackPendingBeforeTime removes pending messages sent before t and credits the
// congestion window for the freed bytes.  Called by receiveWorker to model
// peer-responsiveness as a delivery confirmation.
func (s *SSU2Session) ackPendingBeforeTime(t time.Time) {
	var ackedBytes int
	s.pendingMsgsMu.Lock()
	for seq, p := range s.pendingMsgs {
		if p.sentAt.Before(t) {
			ackedBytes += len(p.data)
			delete(s.pendingMsgs, seq)
		}
	}
	s.pendingMsgsMu.Unlock()
	if ackedBytes > 0 {
		s.congestionCtrl.OnAck(ackedBytes)
	}
}

func (s *SSU2Session) discardRemainingMessages() {
	for {
		select {
		case <-s.sendQueue:
			atomic.AddInt32(&s.sendQueueSize, -1)
		default:
			return
		}
	}
}

// ssu2ReadDeadline is the maximum time to wait for a message before checking session state.
const ssu2ReadDeadline = 5 * time.Minute

func (s *SSU2Session) receiveWorker() {
	defer s.wg.Done()
	buf := make([]byte, 1500)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		if err := s.conn.SetReadDeadline(time.Now().Add(ssu2ReadDeadline)); err != nil {
			s.logger.WithError(err).Error("Failed to set read deadline")
			return
		}

		n, err := s.conn.Read(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			s.logger.WithError(err).Debug("Read error on SSU2 session")
			return
		}

		recvAt := time.Now()
		atomic.AddUint64(&s.bytesReceived, uint64(n))

		// Update RTT estimate using time since last send as a rough proxy.
		if lastSendNano := atomic.LoadInt64(&s.lastSendNano); lastSendNano > 0 {
			if rtt := recvAt.Sub(time.Unix(0, lastSendNano)); rtt > 0 && rtt < maxRTTSample {
				s.rttEstimator.Update(rtt)
			}
		}
		// Any data received means the peer is alive; ACK pending messages.
		s.ackPendingBeforeTime(recvAt)

		msg := i2np.NewI2NPMessage(0)
		if err := msg.UnmarshalBinary(buf[:n]); err != nil {
			s.logger.WithError(err).Debug("Failed to parse I2NP message")
			continue
		}

		select {
		case s.recvChan <- msg:
		case <-s.ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
			atomic.AddUint64(&s.droppedMessages, 1)
			s.logger.Warn("Receive channel full, dropping message")
		}
	}
}

func isTimeout(err error) bool {
	type netError interface {
		Timeout() bool
	}
	if ne, ok := err.(netError); ok {
		return ne.Timeout()
	}
	return false
}
