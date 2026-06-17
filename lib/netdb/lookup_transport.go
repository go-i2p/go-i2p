package netdb

import (
	"context"
	"sync"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// maxPendingLookups bounds the number of in-flight DatabaseLookup requests the
// client will track at once. Each entry is keyed by an attacker-influenced
// target hash, so an unbounded registry would be a remote memory-exhaustion
// vector. In practice the iterative resolver keeps only a handful of lookups
// outstanding (MaxConcurrentQueries per round), so this cap is generous.
const maxPendingLookups = 4096

// lookupReplyRegistry correlates inbound DatabaseStore / DatabaseSearchReply
// messages with outstanding DatabaseLookup requests.
//
// Correlation is keyed by the lookup TARGET KEY rather than by message ID,
// because I2P DatabaseLookup replies do not echo the request's message ID —
// they carry the looked-up key. The iterative resolver issues several parallel
// lookups for the SAME target (one per candidate peer), so multiple waiters can
// be registered under one key. Replies are matched to waiters FIFO: each
// inbound reply wakes exactly one waiter. We cannot bind a reply to the exact
// peer that produced it (the sender hash is dropped before the message reaches
// the processor), but the resolver only needs to know whether *a* peer returned
// the RouterInfo (DatabaseStore) or suggestions (DatabaseSearchReply); any
// surplus DatabaseStore is still persisted to the NetDB by the processor as a
// side effect and surfaces on the next iterative round's local lookup.
type lookupReplyRegistry struct {
	mu      sync.Mutex
	waiters map[common.Hash][]chan lookupResponse
	count   int // total registered channels, bounded by maxPendingLookups
}

func newLookupReplyRegistry() *lookupReplyRegistry {
	return &lookupReplyRegistry{
		waiters: make(map[common.Hash][]chan lookupResponse),
	}
}

// register adds a waiter for the given target key and returns its channel.
// Returns nil if the global pending-lookup cap has been reached, in which case
// the caller must treat the lookup as failed rather than blocking.
func (r *lookupReplyRegistry) register(key common.Hash) chan lookupResponse {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count >= maxPendingLookups {
		return nil
	}
	ch := make(chan lookupResponse, 1)
	r.waiters[key] = append(r.waiters[key], ch)
	r.count++
	return ch
}

// unregister removes a specific waiter channel for a key, typically on timeout
// or cancellation. Safe to call even if the channel was already consumed by a
// delivery.
func (r *lookupReplyRegistry) unregister(key common.Hash, ch chan lookupResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	chans := r.waiters[key]
	for i, c := range chans {
		if c == ch {
			r.waiters[key] = append(chans[:i], chans[i+1:]...)
			r.count--
			break
		}
	}
	if len(r.waiters[key]) == 0 {
		delete(r.waiters, key)
	}
}

// deliver hands a reply to the oldest waiter registered for key. It returns
// true if a waiter consumed the reply, false if there was no matching
// outstanding lookup (in which case the caller may discard the reply; it has
// already been processed/stored elsewhere).
func (r *lookupReplyRegistry) deliver(key common.Hash, msgType int, data []byte) bool {
	r.mu.Lock()
	chans := r.waiters[key]
	if len(chans) == 0 {
		r.mu.Unlock()
		return false
	}
	ch := chans[0]
	r.waiters[key] = chans[1:]
	r.count--
	if len(r.waiters[key]) == 0 {
		delete(r.waiters, key)
	}
	r.mu.Unlock()

	// Channel is buffered with capacity 1 and only ever receives one value, so
	// this send cannot block. The select with default is defensive against a
	// racing unregister that already drained/closed expectations.
	select {
	case ch <- lookupResponse{msgType: msgType, data: data}:
		return true
	default:
		return false
	}
}

// DatabaseLookupClient is the production LookupTransport. It sends direct
// (non-tunnelled) DatabaseLookup messages over transport sessions and blocks
// until the correlated reply arrives or the context is cancelled.
//
// The same instance must be registered as the MessageProcessor's
// LookupReplyDeliverer so that inbound DatabaseStore / DatabaseSearchReply
// messages are routed back into its registry. SendDatabaseLookup (outbound) and
// DeliverLookupReply (inbound) share one lookupReplyRegistry.
type DatabaseLookupClient struct {
	provider SessionProvider
	registry *lookupReplyRegistry
}

// NewDatabaseLookupClient creates a DatabaseLookupClient that sends messages via
// the supplied SessionProvider (typically the router's transport muxer adapter).
func NewDatabaseLookupClient(provider SessionProvider) *DatabaseLookupClient {
	return &DatabaseLookupClient{
		provider: provider,
		registry: newLookupReplyRegistry(),
	}
}

// SendDatabaseLookup sends a DatabaseLookup to peerRI and waits for the
// correlated DatabaseStore or DatabaseSearchReply. It implements LookupTransport.
func (c *DatabaseLookupClient) SendDatabaseLookup(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
	if c.provider == nil {
		return nil, 0, oops.Errorf("lookup client has no session provider")
	}
	if lookup == nil {
		return nil, 0, oops.Errorf("nil lookup message")
	}

	// Register a waiter BEFORE sending so a fast reply cannot race ahead of us.
	ch := c.registry.register(lookup.Key)
	if ch == nil {
		return nil, 0, oops.Errorf("too many pending lookups (cap %d)", maxPendingLookups)
	}
	defer c.registry.unregister(lookup.Key, ch)

	// Serialize the DatabaseLookup body and wrap it in an I2NP message.
	body, err := lookup.MarshalBinary()
	if err != nil {
		return nil, 0, oops.Errorf("failed to marshal DatabaseLookup: %w", err)
	}
	msg := i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeDatabaseLookup)
	msg.SetData(body)

	// Obtain (or establish) a transport session to the peer and queue the send.
	session, err := c.provider.GetSession(peerRI)
	if err != nil {
		return nil, 0, oops.Errorf("failed to get session to peer: %w", err)
	}
	if err := session.QueueSendI2NP(msg); err != nil {
		return nil, 0, oops.Errorf("failed to queue DatabaseLookup: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":     "DatabaseLookupClient.SendDatabaseLookup",
		"target": logutil.HashPrefix(lookup.Key),
	}).Debug("DatabaseLookup sent, awaiting reply")

	// Block until a correlated reply arrives or the context expires.
	select {
	case resp := <-ch:
		return resp.data, resp.msgType, nil
	case <-ctx.Done():
		return nil, 0, oops.Errorf("lookup timed out: %w", ctx.Err())
	}
}

// DeliverLookupReply routes an inbound DatabaseStore / DatabaseSearchReply body
// (already parsed and re-serialized by the processor) to a waiting lookup. It
// implements the i2np.LookupReplyDeliverer interface. Returns true if a pending
// lookup consumed the reply.
func (c *DatabaseLookupClient) DeliverLookupReply(key common.Hash, msgType int, data []byte) bool {
	return c.registry.deliver(key, msgType, data)
}

// Compile-time interface checks.
var (
	_ LookupTransport           = (*DatabaseLookupClient)(nil)
	_ i2np.LookupReplyDeliverer = (*DatabaseLookupClient)(nil)
)
