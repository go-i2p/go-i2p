package noise

import "github.com/go-i2p/go-i2p/lib/i2np"

func (s *NoiseSession) QueueSendI2NP(msg i2np.I2NPMessage) {
	s.SendQueue.Enqueue(msg)
}

func (s *NoiseSession) SendQueueSize() int {
	return s.SendQueue.Size()
}

func (s *NoiseSession) ReadNextI2NP() (i2np.I2NPMessage, error) {
	return i2np.I2NPMessage{}, nil
}
