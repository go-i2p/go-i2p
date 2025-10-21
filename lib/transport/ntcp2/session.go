package ntcp2

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

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
	cleanupCallback func()
	cleanupOnce     sync.Once

	// Logging
	logger *logger.Entry
}

func NewNTCP2Session(conn net.Conn, ctx context.Context, logger *logger.Entry) *NTCP2Session {
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

		// Call cleanup callback to remove session from transport map
		s.callCleanupCallback()
	})
	return err
}

// SetCleanupCallback sets a callback function that will be called when the session closes
func (s *NTCP2Session) SetCleanupCallback(callback func()) {
	s.cleanupCallback = callback
}

// callCleanupCallback calls the cleanup callback (once) if it's set
func (s *NTCP2Session) callCleanupCallback() {
	s.cleanupOnce.Do(func() {
		if s.cleanupCallback != nil {
			s.cleanupCallback()
		}
	})
}

// sendWorker handles sending I2NP messages over the NTCP2 connection.
func (s *NTCP2Session) sendWorker() {
	defer s.wg.Done()

	for {
		select {
		case msg := <-s.sendQueue:
			if !s.processSendQueueMessage(msg) {
				return
			}
		case <-s.ctx.Done():
			return
		}
	}
}

// processSendQueueMessage processes a single I2NP message from the send queue.
// Returns false if an error occurred and the worker should stop, true otherwise.
func (s *NTCP2Session) processSendQueueMessage(msg i2np.I2NPMessage) bool {
	atomic.AddInt32(&s.sendQueueSize, -1)

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
	_, err := s.conn.Write(framedData)
	if err != nil {
		s.setError(WrapNTCP2Error(err, "writing message"))
		return false
	}
	return true
}

// receiveWorker handles receiving I2NP messages from the NTCP2 connection.
func (s *NTCP2Session) receiveWorker() {
	defer s.wg.Done()

	unframer := s.createMessageUnframer()

	for {
		if s.shouldStopReceiving() {
			return
		}

		msg, err := s.readNextMessage(unframer)
		if err != nil {
			s.handleReceiveError(err)
			return
		}

		if !s.queueReceivedMessage(msg) {
			return
		}
	}
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

// readNextMessage reads the next I2NP message from the unframer.
func (s *NTCP2Session) readNextMessage(unframer *I2NPUnframer) (i2np.I2NPMessage, error) {
	return unframer.ReadNextMessage()
}

// handleReceiveError handles errors that occur during message receiving.
func (s *NTCP2Session) handleReceiveError(err error) {
	s.setError(WrapNTCP2Error(err, "reading message"))
}

// queueReceivedMessage attempts to queue a received message to the receive channel.
// Returns false if the session context is done, true if message was queued successfully.
func (s *NTCP2Session) queueReceivedMessage(msg i2np.I2NPMessage) bool {
	select {
	case s.recvChan <- msg:
		return true
	case <-s.ctx.Done():
		return false
	}
}

// setError sets the last error (once) and cancels the session context.
func (s *NTCP2Session) setError(err error) {
	s.errorOnce.Do(func() {
		s.lastError = err
		s.logger.WithError(err).Error("Session error")
		s.cancel()

		// Call cleanup callback to remove session from transport map
		s.callCleanupCallback()
	})
}
