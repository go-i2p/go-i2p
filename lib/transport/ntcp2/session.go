package ntcp2

import (
	"context"
	"net"
	"sync"

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

	return session
}
