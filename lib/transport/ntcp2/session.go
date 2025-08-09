package ntcp2

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/sirupsen/logrus"
)

type NTCP2Session struct {
	// Underlying connection (uses net.Conn interface per guidelines)
	conn net.Conn // Will be *ntcp2.NTCP2Conn internally

	// I2NP message queues
	sendQueue chan i2np.I2NPMessage
	recvChan  chan i2np.I2NPMessage

	// Queue management
	sendQueueSize int32 // atomic counter

	// Error handling
	lastError error
	errorOnce sync.Once

	// Lifecycle management
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once

	// Background workers
	wg sync.WaitGroup

	// Logging
	logger *logrus.Entry
}

func NewNTCP2Session(conn net.Conn, ctx context.Context, logger *logrus.Entry) *NTCP2Session {
	sessionCtx, cancel := context.WithCancel(ctx)
	session := &NTCP2Session{
		conn:          conn,
		sendQueue:     make(chan i2np.I2NPMessage, 100), // Buffered channel for send queue
		recvChan:      make(chan i2np.I2NPMessage, 100), // Buffered channel for receive messages
		ctx:           sessionCtx,
		cancel:        cancel,
		logger:        logger,
		sendQueueSize: 0,
		lastError:     nil,
		errorOnce:     sync.Once{},
		closeOnce:     sync.Once{},
		wg:            sync.WaitGroup{},
	}

	// Start background workers for send and receive
	session.wg.Add(2)
	go session.sendWorker()
	go session.receiveWorker()

	return session
}

// QueueSendI2NP queues an I2NP message to be sent over the session.
// Will block as long as the send queue is full.
func (s *NTCP2Session) QueueSendI2NP(msg i2np.I2NPMessage) {
	select {
	case s.sendQueue <- msg:
		atomic.AddInt32(&s.sendQueueSize, 1)
	case <-s.ctx.Done():
		// Session is closed, ignore the message
		return
	}
}

// SendQueueSize returns how many I2NP messages are not completely sent yet.
func (s *NTCP2Session) SendQueueSize() int {
	return int(atomic.LoadInt32(&s.sendQueueSize))
}

// ReadNextI2NP blocking reads the next fully received I2NP message from this session.
func (s *NTCP2Session) ReadNextI2NP() (i2np.I2NPMessage, error) {
	select {
	case msg := <-s.recvChan:
		return msg, nil
	case <-s.ctx.Done():
		if s.lastError != nil {
			return nil, s.lastError
		}
		return nil, ErrSessionClosed
	}
}

// Close closes the session cleanly.
func (s *NTCP2Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		if s.conn != nil {
			err = s.conn.Close()
		}
		s.wg.Wait()
	})
	return err
}

// sendWorker handles sending I2NP messages over the NTCP2 connection.
func (s *NTCP2Session) sendWorker() {
	defer s.wg.Done()

	for {
		select {
		case msg := <-s.sendQueue:
			atomic.AddInt32(&s.sendQueueSize, -1)

			// Frame the I2NP message
			framedData, err := FrameI2NPMessage(msg)
			if err != nil {
				s.setError(WrapNTCP2Error(err, "framing message"))
				return
			}

			// Write to connection
			_, err = s.conn.Write(framedData)
			if err != nil {
				s.setError(WrapNTCP2Error(err, "writing message"))
				return
			}

		case <-s.ctx.Done():
			return
		}
	}
}

// receiveWorker handles receiving I2NP messages from the NTCP2 connection.
func (s *NTCP2Session) receiveWorker() {
	defer s.wg.Done()

	unframer := NewI2NPUnframer(s.conn)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Read next message
			msg, err := unframer.ReadNextMessage()
			if err != nil {
				s.setError(WrapNTCP2Error(err, "reading message"))
				return
			}

			// Send to receive channel
			select {
			case s.recvChan <- msg:
				// Message queued successfully
			case <-s.ctx.Done():
				return
			}
		}
	}
}

// setError sets the last error (once) and cancels the session context.
func (s *NTCP2Session) setError(err error) {
	s.errorOnce.Do(func() {
		s.lastError = err
		s.logger.WithError(err).Error("Session error")
		s.cancel()
	})
}
