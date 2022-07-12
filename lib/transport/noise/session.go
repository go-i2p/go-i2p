package noise

import (
	cb "github.com/emirpasic/gods/queues/circularbuffer"
	//. "github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
)

type NoiseSession struct {
	*cb.Queue
}

var exampleNoiseSession transport.TransportSession = &NoiseSession{}

func (s *NoiseSession) QueueSendI2NP(msg i2np.I2NPMessage) {
	s.Queue.Enqueue(msg)
}

func (s *NoiseSession) SendQueueSize() int {
	return s.Queue.Size()
}

func (s *NoiseSession) ReadNextI2NP() (i2np.I2NPMessage, error) {
	return i2np.I2NPMessage{}, nil
}

func (s *NoiseSession) Close() error {
	s.Queue.Clear()
	return nil
}

func NewNoiseSession() transport.TransportSession {
	return &NoiseSession{
		Queue: cb.New(1024),
	}
}
