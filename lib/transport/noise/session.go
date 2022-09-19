package noise

import (
	"fmt"
	"net"

	cb "github.com/emirpasic/gods/queues/circularbuffer"
	log "github.com/sirupsen/logrus"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
)

type NoiseSession struct {
	*cb.Queue
	router_info.RouterInfo
	net.Conn
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

func NewNoiseTransportSession(ri router_info.RouterInfo) (transport.TransportSession, error) {
	socket, err := DialNoise("noise", ri)
	if err != nil {
		return nil, err
	}
	return &NoiseSession{
		Queue:      cb.New(1024),
		RouterInfo: ri,
		Conn:       socket,
	}, nil
}

// DialNoise initiates a session with a remote Noise transport, using a
// routerinfo to derive the address to connect to. It doesn't have any chance of
// working yet.
func DialNoise(network string, addr router_info.RouterInfo) (net.Conn, error) {
	for _, addr := range addr.RouterAddresses() {
		log.WithFields(log.Fields{
			"at":   "(DialNoise)",
			"addr": addr,
		}).Log("error parsing router info")
		Dial("noise", string(addr.TransportStyle()))
	}
	return nil, fmt.Errorf("No valid transport discovered.")
}

// Dial initiates a session with a remote Noise transport at a host:port
// or ip:port
func Dial(network, addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}
