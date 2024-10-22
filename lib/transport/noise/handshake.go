package noise

import (
	"github.com/go-i2p/go-i2p/lib/util/logger"
	"sync"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
)

var log = logger.GetLogger()

func (c *NoiseTransport) Handshake(routerInfo router_info.RouterInfo) error {
	log.WithField("router_info", routerInfo.IdentHash()).Debug("Starting Noise handshake")
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	session, err := c.getSession(routerInfo)
	if err != nil {
		log.WithError(err).Error("Failed to get session for handshake")
		return err
	}
	log.Debug("Session obtained for handshake")
	// Set handshakeCond to indicate that this goroutine is committing to
	// running the handshake.
	session.(*NoiseSession).Cond = sync.NewCond(&c.Mutex)
	c.Mutex.Unlock()
	session.(*NoiseSession).Mutex.Lock()
	defer session.(*NoiseSession).Mutex.Unlock()
	c.Mutex.Lock()
	log.Debug("Running outgoing handshake")
	if err := session.(*NoiseSession).RunOutgoingHandshake(); err != nil {
		return err
	}
	log.Debug("Outgoing handshake completed successfully")
	// Wake any other goroutines that are waiting for this handshake to
	// complete.
	session.(*NoiseSession).Cond.Broadcast()
	session.(*NoiseSession).Cond = nil
	log.Debug("Noise handshake completed successfully")
	return nil
}
