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

// SSU2Session implements transport.TransportSession over an SSU2 connection.
type SSU2Session struct {
	conn *ssu2noise.SSU2Conn

	sendQueue     chan i2np.I2NPMessage
	recvChan      chan i2np.I2NPMessage
	sendQueueSize int32

	bytesSent       uint64
	bytesReceived   uint64
	droppedMessages uint64

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

	return &SSU2Session{
		conn:      conn,
		sendQueue: make(chan i2np.I2NPMessage, 256),
		recvChan:  make(chan i2np.I2NPMessage, 256),
		ctx:       sessionCtx,
		cancel:    cancel,
		logger:    sessionLogger,
	}
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
	for {
		select {
		case msg := <-s.sendQueue:
			atomic.AddInt32(&s.sendQueueSize, -1)
			data, err := msg.MarshalBinary()
			if err != nil {
				s.logger.WithError(err).Error("Failed to marshal I2NP message")
				continue
			}
			n, err := s.conn.Write(data)
			if err != nil {
				s.logger.WithError(err).Error("Failed to write message")
				s.discardRemainingMessages()
				return
			}
			atomic.AddUint64(&s.bytesSent, uint64(n))
		case <-s.ctx.Done():
			s.discardRemainingMessages()
			return
		}
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

		atomic.AddUint64(&s.bytesReceived, uint64(n))

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
