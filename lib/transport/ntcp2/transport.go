package ntcp2

import (
	"context"
	"net"
	"sync"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/sirupsen/logrus"
)

type NTCP2Transport struct {
	// Network listener (uses net.Listener interface per guidelines)
	listener net.Listener // Will be *ntcp2.NTCP2Listener internally

	// Configuration
	config   *Config
	identity router_info.RouterInfo

	// Session management
	sessions sync.Map // map[string]*NTCP2Session (keyed by router hash)

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Logging
	logger *logrus.Entry
}

func NewNTCP2Transport(identity router_info.RouterInfo, config *Config) (*NTCP2Transport, error) {
	ctx, cancel := context.WithCancel(context.Background())
	logger := logrus.WithField("component", "ntcp2")
	identityBytes := identity.IdentHash().Bytes()
	// Create a new NTCP2 configuration
	ntcp2Config, err := ntcp2.NewNTCP2Config(identityBytes[:], false)
	if err != nil {
		cancel()
		return nil, err
	}
	config.NTCP2Config = ntcp2Config

	transport := &NTCP2Transport{
		config:   config,
		identity: identity,
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		wg:       sync.WaitGroup{},
		sessions: sync.Map{},
	}

	// Initialize the network listener
	tcpListener, err := net.Listen("tcp", ":0") // Use a random port for listening
	if err != nil {
		return nil, err
	}

	listener, err := ntcp2.NewNTCP2Listener(tcpListener, ntcp2Config)
	if err != nil {
		return nil, err
	}
	transport.listener = listener

	return transport, nil
}
