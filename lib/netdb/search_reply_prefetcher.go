package netdb

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
)

const (
	defaultSuggestionLookupTimeout = 5 * time.Second
	defaultSuggestionCooldown      = 2 * time.Minute
	defaultSuggestionConcurrency   = 4
)

// SearchReplyPrefetcher resolves DatabaseSearchReply peer suggestions into
// RouterInfos so future iterative lookups have a richer local frontier.
// It is intentionally best-effort: failures are logged at debug and do not
// affect the caller's message-processing path.
type SearchReplyPrefetcher struct {
	db       NetworkDatabase
	resolver *KademliaResolver

	lookupTimeout time.Duration
	cooldown      time.Duration
	sem           chan struct{}

	mu          sync.Mutex
	lastAttempt map[common.Hash]time.Time
}

// NewSearchReplyPrefetcher constructs a SearchReplyPrefetcher backed by a
// transport-capable Kademlia resolver.
func NewSearchReplyPrefetcher(db NetworkDatabase, pool *tunnel.Pool, transport LookupTransport, ourHash common.Hash, lookupTimeout time.Duration, maxConcurrent int) *SearchReplyPrefetcher {
	if lookupTimeout <= 0 {
		lookupTimeout = defaultSuggestionLookupTimeout
	}
	if maxConcurrent <= 0 {
		maxConcurrent = defaultSuggestionConcurrency
	}

	resolver := NewKademliaResolverWithTransport(db, pool, transport, ourHash)
	if resolver != nil {
		resolver.SetExploration(false)
	}

	return &SearchReplyPrefetcher{
		db:            db,
		resolver:      resolver,
		lookupTimeout: lookupTimeout,
		cooldown:      defaultSuggestionCooldown,
		sem:           make(chan struct{}, maxConcurrent),
		lastAttempt:   make(map[common.Hash]time.Time),
	}
}

// HandleSearchReply implements i2np.SearchReplyHandler.
func (p *SearchReplyPrefetcher) HandleSearchReply(key common.Hash, peerHashes []common.Hash) {
	if p == nil || p.resolver == nil || len(peerHashes) == 0 {
		return
	}

	for _, peerHash := range peerHashes {
		if p.shouldSkipPeer(peerHash) {
			continue
		}

		go p.prefetchPeer(key, peerHash)
	}
}

func (p *SearchReplyPrefetcher) prefetchPeer(targetKey, peerHash common.Hash) {
	p.sem <- struct{}{}
	defer func() { <-p.sem }()

	if p.hasLocalRouterInfo(peerHash) {
		return
	}

	if _, err := p.resolver.Lookup(peerHash, p.lookupTimeout); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":         "SearchReplyPrefetcher.prefetchPeer",
			"target_key": logutil.HashPrefix(targetKey),
			"peer":       logutil.HashPrefix(peerHash),
		}).Debug("Failed to resolve suggested peer RouterInfo")
		return
	}

	log.WithFields(logger.Fields{
		"at":         "SearchReplyPrefetcher.prefetchPeer",
		"target_key": logutil.HashPrefix(targetKey),
		"peer":       logutil.HashPrefix(peerHash),
	}).Debug("Resolved suggested peer RouterInfo")
}

func (p *SearchReplyPrefetcher) shouldSkipPeer(peerHash common.Hash) bool {
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	if last, ok := p.lastAttempt[peerHash]; ok {
		if now.Sub(last) < p.cooldown {
			return true
		}
	}
	p.lastAttempt[peerHash] = now
	return false
}

func (p *SearchReplyPrefetcher) hasLocalRouterInfo(peerHash common.Hash) bool {
	if p.db == nil {
		return false
	}

	ch := p.db.GetRouterInfo(peerHash)
	if ch == nil {
		return false
	}

	ri, ok := <-ch
	if !ok {
		return false
	}

	_, err := ri.IdentHash()
	return err == nil
}
