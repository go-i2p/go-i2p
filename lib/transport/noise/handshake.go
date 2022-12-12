package noise

import (
	"sync"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport"
)

func (c *NoiseTransport) getSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error) {
	session, err := c.GetSession(routerInfo)
	if err != nil {
		return nil, err
	}
	for {
		if session.(*NoiseSession).handshakeComplete {
			return nil, nil
		}
		if session.(*NoiseSession).Cond == nil {
			break
		}
		session.(*NoiseSession).Cond.Wait()
	}
	return session, nil
}

func (c *NoiseTransport) Handshake(routerInfo router_info.RouterInfo) error {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	session, err := c.getSession(routerInfo)
	if err != nil {
		return err
	}
	// Set handshakeCond to indicate that this goroutine is committing to
	// running the handshake.
	session.(*NoiseSession).Cond = sync.NewCond(&c.Mutex)
	c.Mutex.Unlock()
	session.(*NoiseSession).Mutex.Lock()
	defer session.(*NoiseSession).Mutex.Unlock()
	c.Mutex.Lock()
	//	if c.config.isClient {
	if err := session.(*NoiseSession).RunOutgoingHandshake(); err != nil {
		return err
	}
	// Wake any other goroutines that are waiting for this handshake to
	// complete.
	session.(*NoiseSession).Cond.Broadcast()
	session.(*NoiseSession).Cond = nil
	return nil
}
