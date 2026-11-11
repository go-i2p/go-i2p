// Honest outbound tunnel chain shared by the end-to-end tests.
//
// I2P-002 made outbound I2CP traffic actually tunnel-encapsulated, which removes
// the shortcut the original "integration" tests relied on: capturing the garlic
// message at the transport boundary and re-injecting it by hand into the inbound
// path. Once encapsulation is real, bytes only arrive if a genuine chain of
// relays peels one AES layer each and a tunnel endpoint reassembles the fragments.
//
// e2eOutboundChain supplies that chain, built entirely from production code:
//
//	MessageRouter.transportSend
//	   -> hopA (transit participant)
//	   -> hopB (transit participant)
//	   -> hopC (tunnel endpoint, DTTunnel delivery instructions)
//	   -> InboundMessageHandler.ForwardToTunnel
//	   -> destGW receives the type-19 TunnelGateway addressed at the destination
//
// The destGW boundary is the honest end of what this router can prove today.
// Turning a type-19 that arrives for a REMOTE destination into layered TunnelData
// on that destination's inbound tunnel is the inbound-gateway (IBGW) role, which
// is not implemented - see the I2P-002 notes. Tests therefore assert on the
// garlic envelope that genuinely completed the tunnel, not on remote-client
// delivery, and say so.

package router

import (
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/samber/oops"
	"github.com/stretchr/testify/require"
)

// e2eChainHops is the tunnel length the chain terminates. DefaultTunnelLength is
// 3, so this mirrors what a real build produces.
const e2eChainHops = 3

// e2eOutboundChain is one destination gateway plus the relay hops that can reach it.
type e2eOutboundChain struct {
	table  map[common.Hash]*encapRelay
	hopA   *encapRelay
	hopB   *encapRelay
	hopC   *encapRelay
	destGW *encapRelay

	lease i2cp.LeaseTarget

	mu        sync.Mutex
	garlic    []*i2np.BaseI2NPMessage
	pending   chan struct{}
	closed    bool
	decodeErr error

	nextBase  tunnel.TunnelID
	endpoints []*tunnel.Endpoint
}

func newE2EOutboundChain(t *testing.T, label string) *e2eOutboundChain {
	t.Helper()

	c := &e2eOutboundChain{
		table:    make(map[common.Hash]*encapRelay, e2eChainHops+1),
		pending:  make(chan struct{}, 256),
		nextBase: 0xE2E0_0001,
	}

	c.hopA = newEncapRelay(t, label+"-hop-a", c.table)
	c.hopB = newEncapRelay(t, label+"-hop-b", c.table)
	c.hopC = newEncapRelay(t, label+"-hop-c", c.table)
	c.destGW = newEncapRelay(t, label+"-dest-gw", c.table)

	c.lease = i2cp.LeaseTarget{
		GatewayHash: c.destGW.hash,
		TunnelID:    0xD571_0001,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	// The destination gateway is where the tunnel chain terminates for now: the
	// endpoint's forwarder emits a type-19 TunnelGateway addressed at the
	// destination's inbound tunnel. Capture the inner I2NP so tests can assert on
	// bytes that really crossed every hop.
	c.destGW.onTunnelGateway = func(gw *i2np.TunnelGateway) {
		inner := &i2np.BaseI2NPMessage{}
		if err := inner.UnmarshalBinary(gw.Data); err != nil {
			c.mu.Lock()
			if c.decodeErr == nil {
				c.decodeErr = err
			}
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		c.garlic = append(c.garlic, inner)
		c.mu.Unlock()
		select {
		case c.pending <- struct{}{}:
		default:
		}
	}

	t.Cleanup(c.close)
	return c
}

// LeaseTarget is the addressing the fixture's resolver hands back for every
// destination. A real router resolves this from the NetDB's leaseset; the chain
// stands in for that lookup so the test exercises encapsulation rather than
// discovery.
func (c *e2eOutboundChain) LeaseTarget() i2cp.LeaseTarget { return c.lease }

// TransportSend is the send function for i2cp.NewMessageRouter. It hands each
// record to hop A's production inbound handler, so a send cannot succeed unless
// it left as a real layered TunnelData message.
func (c *e2eOutboundChain) TransportSend() func(common.Hash, i2np.Message) error {
	return func(peer common.Hash, msg i2np.Message) error {
		if msg.Type() != i2np.I2NPMessageTypeTunnelData {
			return oops.Errorf("outbound traffic left as I2NP type %d, not TunnelData", msg.Type())
		}
		if peer != c.hopA.hash {
			return oops.Errorf("record addressed to %x, expected hop A %x", peer[:8], c.hopA.hash[:8])
		}
		return c.hopA.inbound.HandleTunnelData(msg)
	}
}

// AddTunnel builds a ready 3-hop outbound tunnel over this chain and returns the
// TunnelState to place in a pool. Every hop gets its own receive ID and layer
// keys, exactly as a real build distributes them, so the state can act as its own
// creator-side gateway.
func (c *e2eOutboundChain) AddTunnel(t *testing.T) *tunnel.TunnelState {
	t.Helper()

	base := c.nextBase
	c.nextBase += 16

	ot := buildEncapTunnelWithBase(e2eChainHops, base)
	ot.setHop(0, c.hopA.hash)
	ot.setHop(1, c.hopB.hash)
	ot.setHop(2, c.hopC.hash)

	registerEncapTransit(t, c.hopA, ot.keys[0], ot.receiveIDs[0], ot.receiveIDs[1], c.hopB.hash)
	registerEncapTransit(t, c.hopB, ot.keys[1], ot.receiveIDs[1], ot.receiveIDs[2], c.hopC.hash)

	// hopC terminates the tunnel. The records carry DTTunnel instructions for the
	// destination gateway, so the endpoint delegates to its forwarder - its own
	// production InboundMessageHandler - which emits the type-19.
	endpoint, err := tunnel.NewEndpoint(ot.receiveIDs[2], encapEncryptor(t, ot.keys[2]), func([]byte) error {
		return oops.Errorf("chain endpoint ran its local handler for a DTTunnel delivery")
	})
	require.NoError(t, err)
	endpoint.SetForwarder(c.hopC.inbound)
	require.NoError(t, c.hopC.inbound.RegisterTunnel(ot.receiveIDs[2], uint16(base), endpoint))

	c.mu.Lock()
	c.endpoints = append(c.endpoints, endpoint)
	c.mu.Unlock()

	return ot.state
}

// PopGarlic returns the next message that completed the whole tunnel chain, or
// nil if none arrives before the timeout.
func (c *e2eOutboundChain) PopGarlic(timeout time.Duration) *i2np.BaseI2NPMessage {
	deadline := time.After(timeout)
	for {
		c.mu.Lock()
		if len(c.garlic) > 0 {
			g := c.garlic[0]
			c.garlic = c.garlic[1:]
			c.mu.Unlock()
			return g
		}
		err := c.decodeErr
		c.mu.Unlock()
		if err != nil {
			return nil
		}

		select {
		case <-c.pending:
		case <-deadline:
			return nil
		}
	}
}

// PopAllGarlic drains everything that has completed the chain so far.
func (c *e2eOutboundChain) PopAllGarlic() []*i2np.BaseI2NPMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.garlic
	c.garlic = nil
	return out
}

// DecodeError reports a payload that crossed the chain but could not be parsed.
func (c *e2eOutboundChain) DecodeError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.decodeErr
}

func (c *e2eOutboundChain) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	eps := c.endpoints
	c.endpoints = nil
	c.mu.Unlock()

	for _, ep := range eps {
		ep.Stop()
	}
}
