package netdb

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SessionProvider provides access to the transport layer for sending I2NP messages.
// This interface allows the Publisher to send messages to gateway routers without
// tight coupling to the router/transport implementation.
type SessionProvider interface {
	// GetSession obtains a transport session with a router given its RouterInfo.
	// If a session with this router is NOT already made, attempts to create one.
	// Returns an established TransportSession and nil on success.
	// Returns nil and an error on error.
	GetSession(routerInfo router_info.RouterInfo) (I2NPSender, error)
}

// I2NPSender represents a session for sending I2NP messages to a router.
type I2NPSender interface {
	// QueueSendI2NP queues an I2NP message to be sent over the session.
	// Returns an error if the session is closed or send queue is full.
	QueueSendI2NP(msg i2np.Message) error
}

// RouterInfoProvider provides access to the local router's RouterInfo.
// This interface allows the Publisher to get the current RouterInfo without
// tight coupling to the router implementation, enabling easier testing.
type RouterInfoProvider interface {
	// GetRouterInfo returns the current RouterInfo for this router.
	// Returns an error if the RouterInfo cannot be constructed or retrieved.
	GetRouterInfo() (*router_info.RouterInfo, error)
}

// Publisher handles publishing RouterInfo and LeaseSets to floodfill routers.
// Publishing ensures that our router and client destinations can be found
// by other routers in the network.
type Publisher struct {
	// netdb for floodfill router selection
	db NetworkDatabase

	// tunnel pool for sending DatabaseStore messages
	pool *tunnel.Pool

	// inboundPool is used to select a reply tunnel for DatabaseStore acknowledgments.
	// Optional: if nil or no active tunnel is available, reply routing fields remain unset.
	inboundPool *tunnel.Pool

	// fieldMu protects transport from concurrent read/write
	fieldMu sync.RWMutex

	// transport for sending I2NP messages to gateway routers
	transport SessionProvider

	// lookupTransport performs direct DatabaseLookup probes used to verify
	// post-publication RouterInfo retrievability from remote floodfills.
	lookupTransport LookupTransport

	// routerInfoProvider supplies our local RouterInfo for publishing
	routerInfoProvider RouterInfoProvider

	// publishing control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// configuration
	routerInfoInterval time.Duration // how often to republish RouterInfo
	leaseSetInterval   time.Duration // how often to republish LeaseSets
	floodfillCount     int           // how many floodfills to publish to

	// verification settings and counters
	verifyTimeout            time.Duration
	routerInfoPublishSuccess atomic.Uint64
	routerInfoPublishFail    atomic.Uint64
	routerInfoVerifySuccess  atomic.Uint64
	routerInfoVerifyFail     atomic.Uint64
}

type publisherLoopSpec struct {
	interval time.Duration
	action   func()
}

// PublisherConfig holds configuration for database publishing
type PublisherConfig struct {
	// RouterInfoInterval is how often to republish our RouterInfo (default: 30 minutes)
	RouterInfoInterval time.Duration

	// LeaseSetInterval is how often to republish LeaseSets (default: 5 minutes)
	LeaseSetInterval time.Duration

	// FloodfillCount is how many closest floodfills to publish to (default: 4)
	FloodfillCount int
}

// DefaultPublisherConfig returns the default publisher configuration
func DefaultPublisherConfig() PublisherConfig {
	return PublisherConfig{
		RouterInfoInterval: 30 * time.Minute,
		LeaseSetInterval:   5 * time.Minute,
		FloodfillCount:     4,
	}
}

// NewPublisher creates a new database publisher.
// The publisher periodically distributes RouterInfo and LeaseSets to
// the closest floodfill routers based on Kademlia XOR distance.
//
// Parameters:
//   - db: NetworkDatabase for floodfill router selection
//   - pool: Tunnel pool for sending DatabaseStore messages (can be nil initially)
//   - transport: TransportManager for sending I2NP messages to gateway routers (can be nil initially)
//   - routerInfoProvider: Provider for accessing local RouterInfo (can be nil if not publishing RouterInfo)
//   - config: Publisher configuration (intervals, floodfill count)
func NewPublisher(db NetworkDatabase, pool *tunnel.Pool, transport SessionProvider, routerInfoProvider RouterInfoProvider, config PublisherConfig) *Publisher {
	ctx, cancel := context.WithCancel(context.Background())

	return &Publisher{
		db:                 db,
		pool:               pool,
		transport:          transport,
		routerInfoProvider: routerInfoProvider,
		ctx:                ctx,
		cancel:             cancel,
		routerInfoInterval: config.RouterInfoInterval,
		leaseSetInterval:   config.LeaseSetInterval,
		floodfillCount:     config.FloodfillCount,
		verifyTimeout:      15 * time.Second,
	}
}

// SetInboundPool sets the inbound tunnel pool used for DatabaseStore reply routing.
// When configured and active inbound tunnels exist, published DatabaseStore messages
// include ReplyTunnelID/ReplyGateway so floodfill acknowledgments have a valid return path.
func (p *Publisher) SetInboundPool(inboundPool *tunnel.Pool) {
	p.fieldMu.Lock()
	p.inboundPool = inboundPool
	p.fieldMu.Unlock()
}

// Start begins periodic publishing of RouterInfo and LeaseSets.
// Publishing runs in background goroutines until Stop is called.
func (p *Publisher) Start() error {
	if p.pool == nil {
		return oops.Errorf("tunnel pool required for publishing")
	}
	p.fieldMu.RLock()
	transport := p.transport
	p.fieldMu.RUnlock()
	if transport == nil {
		return oops.Errorf("transport manager required for publishing")
	}

	log.WithFields(logger.Fields{
		"router_info_interval": p.routerInfoInterval,
		"lease_set_interval":   p.leaseSetInterval,
		"floodfill_count":      p.floodfillCount,
	}).Info("Starting database publisher")

	for _, loop := range p.publisherLoopSpecs() {
		p.wg.Add(1)
		go p.runPublisherLoop(loop)
	}

	return nil
}

// Stop halts database publishing and waits for in-flight publishes to complete.
func (p *Publisher) Stop() {
	log.WithFields(logger.Fields{"at": "Stop"}).Info("Stopping database publisher")
	p.cancel()
	p.wg.Wait()
	log.WithFields(logger.Fields{"at": "Stop"}).Info("Database publisher stopped")
}

// periodicLoop runs a periodic action at the specified interval until context is cancelled.
// It calls the action immediately on start, then again after each tick.
// The caller should call wg.Done() to signal completion (via defer in the goroutine).
func (p *Publisher) periodicLoop(interval time.Duration, action func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Execute action immediately on start
	action()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			action()
		}
	}
}

func (p *Publisher) publisherLoopSpecs() []publisherLoopSpec {
	return []publisherLoopSpec{
		{interval: p.routerInfoInterval, action: p.publishOurRouterInfo},
		{interval: p.leaseSetInterval, action: p.publishAllLeaseSets},
	}
}

func (p *Publisher) runPublisherLoop(loop publisherLoopSpec) {
	defer p.wg.Done()
	p.periodicLoop(loop.interval, loop.action)
}

// publishOurRouterInfo publishes our local RouterInfo to floodfill routers.
// This makes our router discoverable in the I2P network by distributing our
// RouterInfo to the closest floodfill routers in the DHT.
func (p *Publisher) publishOurRouterInfo() {
	log.WithFields(logger.Fields{"at": "publishOurRouterInfo"}).Debug("Publishing our RouterInfo")

	// Check if RouterInfo provider is configured
	if p.routerInfoProvider == nil {
		log.WithFields(logger.Fields{"at": "publishOurRouterInfo"}).Debug("RouterInfoProvider not configured, skipping RouterInfo publishing")
		return
	}

	// Get our local RouterInfo from the provider
	ri, err := p.routerInfoProvider.GetRouterInfo()
	if err != nil {
		log.WithError(err).Warn("Failed to get local RouterInfo for publishing")
		return
	}

	// DIAGNOSTIC: Log our RouterInfo identity
	riHash, err := ri.IdentHash()
	if err == nil {
		log.WithFields(logger.Fields{
			"at":                     "publishOurRouterInfo",
			"router_identity_prefix": riHash.String()[:16],
			"router_identity_full":   riHash.String(),
		}).Info("RouterInfo details before publishing")
	}

	// Validate RouterInfo before publishing
	if !ri.IsValid() {
		log.WithFields(logger.Fields{"at": "publishOurRouterInfo"}).Warn("Local RouterInfo is invalid, skipping publishing")
		return
	}
	if err := ri.ValidatePublishable(); err != nil {
		log.WithError(err).Warn("Local RouterInfo contains unpublishable addresses, skipping publishing")
		return
	}

	// Publish the RouterInfo using the existing PublishRouterInfo method
	if err := p.PublishRouterInfo(*ri); err != nil {
		log.WithError(err).Warn("Failed to publish local RouterInfo")
		return
	}

	log.WithFields(logger.Fields{
		"at":              "publishOurRouterInfo",
		"router_identity": riHash.String()[:16],
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}).Info("Successfully published our RouterInfo to floodfill routers")
}

// ForceRouterInfoRepublish immediately republishes our RouterInfo to all known floodfill routers.
// This should be called when:
//  1. Encryption keys are regenerated or detected as inconsistent
//  2. Garlic message decryption failures spike (indicates peers have old RouterInfo)
//  3. Router restarts and needs to propagate new identity to network
//
// Without forced republish, it can take 30+ minutes for the network to converge
// on the new RouterInfo, causing 100% garlic decryption failures during that window.
func (p *Publisher) ForceRouterInfoRepublish() error {
	log.WithFields(logger.Fields{
		"at":        "ForceRouterInfoRepublish",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"reason":    "forced republish to propagate key changes and resolve garlic decryption conflicts",
	}).Info("Forcing immediate RouterInfo republish to all floodfill routers")

	p.publishOurRouterInfo()
	return nil
}

// publishAllLeaseSets publishes all LeaseSets in the database
func (p *Publisher) publishAllLeaseSets() {
	log.WithFields(logger.Fields{"at": "publishAllLeaseSets"}).Debug("Publishing all LeaseSets")

	// Get all LeaseSets from the database
	leaseSets := p.db.GetAllLeaseSets()
	if len(leaseSets) == 0 {
		log.Trace("No LeaseSets to publish")
		return
	}

	log.WithField("count", len(leaseSets)).Debug("Found LeaseSets to publish")

	// Publish each LeaseSet to floodfill routers
	for _, lsEntry := range leaseSets {
		if err := p.publishLeaseSetEntry(lsEntry); err != nil {
			log.WithError(err).WithField("hash", logutil.HashPrefix(lsEntry.Hash)).Warn("Failed to publish LeaseSet")
		}
	}

	log.WithField("count", len(leaseSets)).Debug("Completed publishing all LeaseSets")
}

// publishLeaseSetEntry publishes a single LeaseSetEntry to floodfill routers.
// This is a helper method that determines which type of LeaseSet to publish.
// The DatabaseStore type byte must match the actual LeaseSet type per the I2P spec:
//   - DatabaseStoreTypeLeaseSet (1) for original LeaseSet
//   - DatabaseStoreTypeLeaseSet2 (3) for LeaseSet2
//   - DatabaseStoreTypeEncryptedLeaseSet (5) for EncryptedLeaseSet
//   - DatabaseStoreTypeMetaLeaseSet (7) for MetaLeaseSet
func (p *Publisher) publishLeaseSetEntry(lsEntry LeaseSetEntry) error {
	// Determine which type of LeaseSet we have, serialize it, and select the correct store type
	var lsBytes []byte
	var err error
	var storeType byte

	switch {
	case lsEntry.Entry.LeaseSet != nil:
		lsBytes, err = lsEntry.Entry.LeaseSet.Bytes()
		storeType = i2np.DatabaseStoreTypeLeaseSet
	case lsEntry.Entry.LeaseSet2 != nil:
		lsBytes, err = lsEntry.Entry.LeaseSet2.Bytes()
		storeType = i2np.DatabaseStoreTypeLeaseSet2
	case lsEntry.Entry.EncryptedLeaseSet != nil:
		lsBytes, err = lsEntry.Entry.EncryptedLeaseSet.Bytes()
		storeType = i2np.DatabaseStoreTypeEncryptedLeaseSet
	case lsEntry.Entry.MetaLeaseSet != nil:
		lsBytes, err = lsEntry.Entry.MetaLeaseSet.Bytes()
		storeType = i2np.DatabaseStoreTypeMetaLeaseSet
	default:
		return oops.Errorf("LeaseSetEntry contains no valid LeaseSet data")
	}

	if err != nil {
		return oops.Errorf("failed to serialize LeaseSet: %w", err)
	}

	// Select closest floodfill routers
	floodfills, err := p.selectFloodfillsForPublishing(lsEntry.Hash)
	if err != nil {
		return oops.Errorf("failed to select floodfills: %w", err)
	}

	// Send DatabaseStore message to each selected floodfill with the correct store type
	return p.sendDatabaseStoreMessages(lsEntry.Hash, lsBytes, storeType, floodfills)
}

// publishLeaseSetObject is an internal method that publishes a typed LeaseSet object.
// This is used internally by publishAllLeaseSets to publish LeaseSets retrieved from the database.
// Note: This method publishes original LeaseSets (type 1), not LeaseSet2.
func (p *Publisher) publishLeaseSetObject(hash common.Hash, ls lease_set.LeaseSet) error {
	log.WithField("hash", logutil.HashPrefixPlain(hash)).Debug("Publishing LeaseSet")

	// Validate LeaseSet before attempting serialization
	if err := ls.Validate(); err != nil {
		return oops.Errorf("invalid LeaseSet: %w", err)
	}

	// Select closest floodfill routers
	floodfills, err := p.selectFloodfillsForPublishing(hash)
	if err != nil {
		return oops.Errorf("failed to select floodfills: %w", err)
	}

	// Send DatabaseStore message to each selected floodfill
	// Use DatabaseStoreTypeLeaseSet (1) since this is an original LeaseSet, not LeaseSet2
	lsBytes, err := ls.Bytes()
	if err != nil {
		return oops.Errorf("failed to serialize LeaseSet: %w", err)
	}
	return p.sendDatabaseStoreMessages(hash, lsBytes, i2np.DatabaseStoreTypeLeaseSet, floodfills)
}

// PublishLeaseSet publishes raw LeaseSet bytes to floodfill routers.
// This method satisfies the i2cp.LeaseSetPublisher interface and is used
// for publishing I2CP client LeaseSets (which are LeaseSet2) via the tunnel-anonymous path.
// The provided bytes are assumed to be a serialized LeaseSet2 (dataType=3).
//
// H-2 Consolidation: This method enables complete migration to tunnel-anonymous publishing
// for all LeaseSets, eliminating the separate router.LeaseSetPublisher direct-session approach.
//
// Parameters:
//   - hash: The destination hash (SHA256 of the destination)
//   - leaseSetData: Raw serialized LeaseSet2 bytes
//
// Returns an error if publishing to floodfill routers fails.
func (p *Publisher) PublishLeaseSet(hash common.Hash, leaseSetData []byte) error {
	log.WithField("hash", logutil.HashPrefixPlain(hash)).Debug("Publishing LeaseSet via PublishLeaseSet")

	// Validate input
	if len(leaseSetData) == 0 {
		return oops.Errorf("cannot publish empty LeaseSet bytes")
	}

	// CRITICAL-3 FIX: Store LeaseSet in local NetDB for internal use only.
	// Uses StoreOwnLeaseSet to mark as "local-use-only" so it won't be served
	// to external lookup queries, maintaining privacy. This ensures:
	// 1. Local router can find its own inbound tunnel entrance points
	// 2. Periodic re-publication loop includes session-created LeaseSets
	// 3. Other local components can query LeaseSets via NetDB
	// 4. Privacy: external lookups don't leak our session LeaseSets
	// Without this store, session-created LeaseSets are invisible locally and inbound
	// tunnels are unreachable - external routers know about them but THIS router doesn't.
	if err := p.db.StoreOwnLeaseSet(hash, leaseSetData, i2np.DatabaseStoreTypeLeaseSet2); err != nil {
		log.WithField("hash", logutil.HashPrefixPlain(hash)).Warn("Failed to store LeaseSet in local NetDB during publication")
		// Log the error but continue with network publication (best-effort pattern)
	}

	// Select closest floodfill routers
	floodfills, err := p.selectFloodfillsForPublishing(hash)
	if err != nil {
		return oops.Errorf("failed to select floodfills: %w", err)
	}

	// Assume LeaseSet2 (dataType=3) for I2CP published content
	// This ensures consistent tunnel-anonymous publishing via the I2P network
	return p.sendDatabaseStoreMessages(hash, leaseSetData, i2np.DatabaseStoreTypeLeaseSet2, floodfills)
}

// PublishRouterInfo publishes a specific RouterInfo to floodfill routers
func (p *Publisher) PublishRouterInfo(ri router_info.RouterInfo) error {
	hash, err := ri.IdentHash()
	if err != nil {
		return oops.Errorf("failed to get router hash: %w", err)
	}
	log.WithFields(logger.Fields{
		"at":        "PublishRouterInfo",
		"hash":      logutil.HashPrefixPlain(hash),
		"full_hash": hash.String(),
	}).Info("Publishing RouterInfo to floodfills")

	// Select closest floodfill routers
	floodfills, err := p.selectFloodfillsForPublishing(hash)
	if err != nil {
		return oops.Errorf("failed to select floodfills: %w", err)
	}

	// DIAGNOSTIC: Log which floodfills we're publishing to
	if len(floodfills) > 0 {
		ffHashes := make([]string, 0, len(floodfills))
		for _, ff := range floodfills {
			ffHash, _ := ff.IdentHash()
			ffHashes = append(ffHashes, ffHash.String()[:16])
		}
		log.WithFields(logger.Fields{
			"at":               "PublishRouterInfo",
			"floodfill_count":  len(floodfills),
			"floodfill_hashes": ffHashes,
		}).Info("Selected floodfill routers for publication")
	}

	// Send DatabaseStore message to each selected floodfill.
	// Per I2P spec, RouterInfo data in DatabaseStore must be gzip-compressed.
	riBytes, err := ri.Bytes()
	if err != nil {
		return oops.Errorf("failed to serialize RouterInfo: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":                "PublishRouterInfo",
		"router_info_bytes": len(riBytes),
		"hash":              hash.String()[:16],
	}).Debug("RouterInfo serialized for distribution")

	compressed, err := gzipCompress(riBytes)
	if err != nil {
		return oops.Errorf("failed to gzip-compress RouterInfo: %w", err)
	}

	// RouterInfo DatabaseStore payload MUST be: 2-byte compressed length + gzip bytes.
	payload := make([]byte, 2+len(compressed))
	binary.BigEndian.PutUint16(payload[:2], uint16(len(compressed)))
	copy(payload[2:], compressed)

	log.WithFields(logger.Fields{
		"at":                "PublishRouterInfo",
		"uncompressed_size": len(riBytes),
		"compressed_size":   len(compressed),
		"hash":              hash.String()[:16],
	}).Debug("RouterInfo compressed for transmission")

	if err := p.sendDatabaseStoreMessagesAtLeastOne(hash, payload, i2np.DatabaseStoreTypeRouterInfo, floodfills); err != nil {
		p.routerInfoPublishFail.Add(1)
		return err
	}

	const verifyAttempts = 4
	const verifyRetryDelay = 2 * time.Second

	var verifyErr error
	for attempt := 1; attempt <= verifyAttempts; attempt++ {
		verifyErr = p.verifyRouterInfoRetrievable(hash, floodfills)
		if verifyErr == nil {
			p.routerInfoPublishSuccess.Add(1)
			p.routerInfoVerifySuccess.Add(1)
			return nil
		}

		if attempt < verifyAttempts {
			log.WithError(verifyErr).WithFields(logger.Fields{
				"at":      "PublishRouterInfo",
				"hash":    logutil.HashPrefixPlain(hash),
				"attempt": attempt,
				"max":     verifyAttempts,
			}).Warn("RouterInfo verification failed; retrying")
			time.Sleep(verifyRetryDelay)
		}
	}

	p.routerInfoPublishFail.Add(1)
	p.routerInfoVerifyFail.Add(1)
	return oops.Errorf("post-publish RouterInfo verification failed after %d attempts: %w", verifyAttempts, verifyErr)
}

// verifyRouterInfoRetrievable probes selected floodfills with a RouterInfo lookup
// for our hash. Success requires at least one DatabaseStore RouterInfo response
// matching the target hash, proving network retrievability beyond local publish.
func (p *Publisher) verifyRouterInfoRetrievable(target common.Hash, floodfills []router_info.RouterInfo) error {
	p.fieldMu.RLock()
	transport := p.lookupTransport
	p.fieldMu.RUnlock()
	if transport == nil {
		log.WithFields(logger.Fields{
			"at":     "verifyRouterInfoRetrievable",
			"target": logutil.HashPrefixPlain(target),
			"reason": "lookup transport not configured; skipping post-publish verification",
		}).Warn("RouterInfo publication verification skipped")
		return nil
	}

	if len(floodfills) == 0 {
		return oops.Errorf("no floodfills available for RouterInfo verification")
	}

	for _, ff := range floodfills {
		ctx, cancel := context.WithTimeout(p.ctx, p.verifyTimeout)
		from := target
		if p.routerInfoProvider != nil {
			if ri, err := p.routerInfoProvider.GetRouterInfo(); err == nil {
				if riHash, err := ri.IdentHash(); err == nil {
					from = riHash
				}
			}
		}
		lookup := i2np.NewDatabaseLookup(target, from, i2np.DatabaseLookupFlagTypeRI, nil)
		respData, msgType, err := transport.SendDatabaseLookup(ctx, ff, lookup)
		cancel()
		if err != nil {
			continue
		}
		if msgType != i2np.I2NPMessageTypeDatabaseStore {
			continue
		}
		store := &i2np.DatabaseStore{BaseI2NPMessage: i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeDatabaseStore)}
		if err := store.UnmarshalBinary(respData); err != nil {
			continue
		}
		if store.GetLeaseSetType() == i2np.DatabaseStoreTypeRouterInfo && store.GetStoreKey() == target {
			log.WithFields(logger.Fields{
				"at":     "verifyRouterInfoRetrievable",
				"target": logutil.HashPrefixPlain(target),
			}).Info("RouterInfo post-publish verification succeeded")
			return nil
		}
	}

	return oops.Errorf("post-publish RouterInfo verification failed: no floodfill returned matching RouterInfo")
}

func bindPlainTCPListener(listenerAddress string, requestedPort int) (net.Listener, string, error) {
	listenCfg := net.ListenConfig{}

	host, _, err := net.SplitHostPort(listenerAddress)
	if err != nil {
		if requestedPort == 0 && listenerAddress == "" {
			host = ""
		} else {
			return nil, "", oops.Wrapf(err, "invalid listener address: %s", listenerAddress)
		}
	}

	bindAddr := listenerAddress
	if requestedPort != 0 {
		if host == "" {
			bindAddr = ":" + strconv.Itoa(requestedPort)
		} else if strings.Contains(host, ":") {
			bindAddr = fmt.Sprintf("[%s]:%d", host, requestedPort)
		} else {
			bindAddr = fmt.Sprintf("%s:%d", host, requestedPort)
		}
	}

	listener, err := listenCfg.Listen(context.Background(), "tcp", bindAddr)
	if err != nil {
		return nil, "", oops.Wrapf(err, "failed to create TCP listener on %s", bindAddr)
	}

	return listener, listener.Addr().String(), nil
}

// selectFloodfillsForPublishing selects the closest floodfills for a given hash.
// Per the I2P spec the DHT key used for peer selection is the routing key,
// not the raw hash: routing_key = SHA256(hash || yyyyMMdd_UTC).
func (p *Publisher) selectFloodfillsForPublishing(hash common.Hash) ([]router_info.RouterInfo, error) {
	floodfills, err := p.db.SelectFloodfillRouters(RoutingKey(hash, time.Now()), p.floodfillCount)
	if err != nil {
		log.WithError(err).Error("Failed to select floodfill routers")
		return nil, err
	}

	eligible := make([]router_info.RouterInfo, 0, len(floodfills))
	for _, ri := range floodfills {
		if isEligiblePublishFloodfill(ri) {
			eligible = append(eligible, ri)
		}
	}

	if len(eligible) == 0 {
		log.WithFields(logger.Fields{
			"hash":       logutil.HashPrefixPlain(hash),
			"floodfills": len(floodfills),
		}).Warn("No eligible floodfills after publication hardening; falling back to raw floodfill set")
		return floodfills, nil
	}

	log.WithFields(logger.Fields{
		"hash":                logutil.HashPrefixPlain(hash),
		"floodfills":          len(floodfills),
		"eligible_floodfills": len(eligible),
	}).Debug("Selected floodfill routers for publishing")

	return eligible, nil
}

// isEligiblePublishFloodfill applies additional publication-time eligibility checks
// beyond the caps="f" floodfill marker. Publishing to unreachable or stale floodfills
// can make RouterInfo look successfully published locally while remaining
// unretrievable by remote routers.
func isEligiblePublishFloodfill(ri router_info.RouterInfo) bool {
	if !strings.ContainsRune(ri.RouterCapabilities(), 'R') || strings.ContainsRune(ri.RouterCapabilities(), 'H') {
		return false
	}

	direct, viaIntro := hasReachableAddress(&ri)
	if !direct && !viaIntro {
		return false
	}

	if published := ri.Published(); published != nil {
		if time.Since(published.Time()) > maxRouterInfoAge {
			return false
		}
	}

	return true
}

// sendDatabaseStoreMessages sends DatabaseStore messages to specified floodfills
func (p *Publisher) sendDatabaseStoreMessages(hash common.Hash, data []byte, dataType byte, floodfills []router_info.RouterInfo) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(floodfills))

	for _, ff := range floodfills {
		wg.Add(1)
		go func(floodfill router_info.RouterInfo) {
			defer wg.Done()

			if err := p.sendDatabaseStoreToFloodfill(hash, data, dataType, floodfill); err != nil {
				errChan <- err
			}
		}(ff)
	}

	wg.Wait()
	close(errChan)

	// Collect any errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		// Build a summary of error messages for debugging
		errMsgs := make([]string, 0, len(errors))
		for _, e := range errors {
			errMsgs = append(errMsgs, e.Error())
		}
		log.WithFields(logger.Fields{
			"hash":         logutil.HashPrefixPlain(hash),
			"errors":       len(errors),
			"total":        len(floodfills),
			"error_detail": errMsgs,
		}).Warn("Some DatabaseStore messages failed to send")
		return oops.Errorf("failed to send to %d of %d floodfills: first error: %w", len(errors), len(floodfills), errors[0])
	}

	log.WithFields(logger.Fields{
		"hash":       logutil.HashPrefixPlain(hash),
		"floodfills": len(floodfills),
	}).Debug("Successfully published to all floodfills")

	return nil
}

// sendDatabaseStoreMessagesAtLeastOne sends DatabaseStore messages and treats
// partial delivery as success as long as at least one floodfill accepted the
// message. This is used for RouterInfo publication so transient transport
// outages do not make publication fail when we still reached part of the
// network and can be flooded onward.
func (p *Publisher) sendDatabaseStoreMessagesAtLeastOne(hash common.Hash, data []byte, dataType byte, floodfills []router_info.RouterInfo) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(floodfills))

	for _, ff := range floodfills {
		wg.Add(1)
		go func(floodfill router_info.RouterInfo) {
			defer wg.Done()

			if err := p.sendDatabaseStoreToFloodfill(hash, data, dataType, floodfill); err != nil {
				errChan <- err
			}
		}(ff)
	}

	wg.Wait()
	close(errChan)

	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	successes := len(floodfills) - len(errors)
	if successes <= 0 {
		if len(errors) == 0 {
			return oops.Errorf("failed to send to any floodfill: no floodfills selected")
		}
		return oops.Errorf("failed to send to any floodfill (%d attempted): first error: %w", len(floodfills), errors[0])
	}

	if len(errors) > 0 {
		errMsgs := make([]string, 0, len(errors))
		for _, e := range errors {
			errMsgs = append(errMsgs, e.Error())
		}
		log.WithFields(logger.Fields{
			"hash":         logutil.HashPrefixPlain(hash),
			"successes":    successes,
			"errors":       len(errors),
			"total":        len(floodfills),
			"error_detail": errMsgs,
		}).Warn("RouterInfo publish reached at least one floodfill; continuing despite partial send failures")
	} else {
		log.WithFields(logger.Fields{
			"hash":       logutil.HashPrefixPlain(hash),
			"floodfills": len(floodfills),
		}).Debug("Successfully published to all floodfills")
	}

	return nil
}

// sendDatabaseStoreToFloodfill sends a DatabaseStore message to a specific floodfill
// through an outbound tunnel for anonymity. This method coordinates the tunnel selection,
// message creation, and delivery to the gateway router.
func (p *Publisher) sendDatabaseStoreToFloodfill(hash common.Hash, data []byte, dataType byte, floodfill router_info.RouterInfo) error {
	// For RouterInfo publication, prefer direct delivery to the selected floodfill.
	// This guarantees destination targeting for the highest-impact publication path.
	if dataType == i2np.DatabaseStoreTypeRouterInfo {
		ffHash, err := floodfill.IdentHash()
		if err != nil {
			return oops.Errorf("failed to get floodfill hash: %w", err)
		}

		log.WithFields(logger.Fields{
			"data_hash":      logutil.HashPrefixPlain(hash),
			"floodfill_hash": logutil.HashPrefixPlain(ffHash),
		}).Debug("Sending RouterInfo DatabaseStore directly to selected floodfill")

		if err := p.sendDatabaseStoreDirect(hash, data, dataType, floodfill); err != nil {
			if errors.Is(err, transport.ErrNoTransportAvailable) || strings.Contains(err.Error(), "no transports available") || strings.Contains(err.Error(), "transport manager not available") {
				log.WithFields(logger.Fields{
					"data_hash":      logutil.HashPrefixPlain(hash),
					"floodfill_hash": logutil.HashPrefixPlain(ffHash),
					"reason":         err.Error(),
				}).Warn("Direct RouterInfo publish unavailable; falling back to tunnel delivery")

				selectedTunnel, gatewayHash, tunnelErr := p.selectAndValidateTunnel()
				if tunnelErr != nil {
					return err
				}

				tunnelGateway, tunnelErr := p.createTunnelGatewayMessage(hash, data, dataType, selectedTunnel.ID)
				if tunnelErr != nil {
					return tunnelErr
				}

				if tunnelErr = p.sendMessageThroughGateway(gatewayHash, tunnelGateway); tunnelErr != nil {
					return tunnelErr
				}

				log.WithFields(logger.Fields{
					"data_hash":      logutil.HashPrefixPlain(hash),
					"floodfill_hash": logutil.HashPrefixPlain(ffHash),
					"tunnel_id":      selectedTunnel.ID,
					"gateway_hash":   logutil.HashPrefixPlain(gatewayHash),
				}).Debug("RouterInfo DatabaseStore sent through fallback tunnel")

				return nil
			}
			return err
		}
		return nil
	}

	// For non-RouterInfo entries keep tunnel-anonymous publication behavior.
	selectedTunnel, gatewayHash, err := p.selectAndValidateTunnel()
	if err != nil {
		return err
	}

	ffHash, err := floodfill.IdentHash()
	if err != nil {
		return oops.Errorf("failed to get floodfill hash: %w", err)
	}

	log.WithFields(logger.Fields{
		"data_hash":      logutil.HashPrefixPlain(hash),
		"floodfill_hash": logutil.HashPrefixPlain(ffHash),
		"tunnel_id":      selectedTunnel.ID,
	}).Trace("Sending DatabaseStore message to floodfill through tunnel")

	// Create and wrap DatabaseStore message for tunnel delivery
	tunnelGateway, err := p.createTunnelGatewayMessage(hash, data, dataType, selectedTunnel.ID)
	if err != nil {
		return err
	}

	log.WithFields(logger.Fields{
		"tunnel_id":        selectedTunnel.ID,
		"gateway_hash":     logutil.HashPrefixPlain(gatewayHash),
		"floodfill_hash":   logutil.HashPrefixPlain(ffHash),
		"gateway_msg_type": tunnelGateway.Type(),
	}).Debug("Sending DatabaseStore through tunnel gateway")

	// Send message through gateway router
	if err := p.sendMessageThroughGateway(gatewayHash, tunnelGateway); err != nil {
		return err
	}

	log.WithFields(logger.Fields{
		"data_hash":      logutil.HashPrefixPlain(hash),
		"floodfill_hash": logutil.HashPrefixPlain(ffHash),
		"tunnel_id":      selectedTunnel.ID,
		"gateway_hash":   logutil.HashPrefixPlain(gatewayHash),
	}).Debug("DatabaseStore sent to tunnel gateway for transmission")

	return nil
}

// sendDatabaseStoreDirect sends a DatabaseStore message directly to a floodfill
// over the transport session. This is only used as a bootstrap path for
// RouterInfo publication when no outbound exploratory tunnel is available yet.
func (p *Publisher) sendDatabaseStoreDirect(hash common.Hash, data []byte, dataType byte, floodfill router_info.RouterInfo) error {
	msg, err := p.createDatabaseStoreMessage(hash, data, dataType)
	if err != nil {
		return err
	}

	ffHash, err := floodfill.IdentHash()
	if err != nil {
		return oops.Errorf("failed to get floodfill hash: %w", err)
	}

	log.WithFields(logger.Fields{
		"data_hash":      logutil.HashPrefixPlain(hash),
		"floodfill_hash": logutil.HashPrefixPlain(ffHash),
		"msg_type":       msg.Type(),
	}).Debug("Sending DatabaseStore directly to floodfill")

	p.fieldMu.RLock()
	transport := p.transport
	p.fieldMu.RUnlock()
	if transport == nil {
		return oops.Errorf("transport manager not available")
	}

	session, err := transport.GetSession(floodfill)
	if err != nil {
		return oops.Errorf("failed to get transport session to floodfill: %w", err)
	}
	if err := session.QueueSendI2NP(msg); err != nil {
		return oops.Errorf("failed to queue direct DatabaseStore transmission: %w", err)
	}
	return nil
}

// selectAndValidateTunnel selects an active outbound tunnel and validates it has hops.
// Retries up to 3 times with a short delay to handle transient tunnel unavailability
// during startup when tunnels are still being built.
// Returns the selected tunnel, gateway hash, and any error encountered.
func (p *Publisher) selectAndValidateTunnel() (*tunnel.TunnelState, common.Hash, error) {
	const maxRetries = 3
	const retryDelay = 2 * time.Second

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		selectedTunnel, gatewayHash, err := p.attemptTunnelSelection()
		if err == nil {
			return selectedTunnel, gatewayHash, nil
		}

		lastErr = err
		if attempt < maxRetries-1 {
			log.WithField("attempt", attempt+1).Debug("Tunnel selection failed, retrying after delay")
			time.Sleep(retryDelay)
		}
	}
	return nil, common.Hash{}, lastErr
}

// attemptTunnelSelection attempts to select a tunnel and validate it has hops.
func (p *Publisher) attemptTunnelSelection() (*tunnel.TunnelState, common.Hash, error) {
	selectedTunnel := p.pool.SelectTunnel()
	if selectedTunnel == nil {
		return nil, common.Hash{}, oops.Errorf("no active outbound tunnels available")
	}

	if len(selectedTunnel.Hops) == 0 {
		return nil, common.Hash{}, oops.Errorf("tunnel has no hops")
	}

	gatewayHash := selectedTunnel.Hops[0]
	return selectedTunnel, gatewayHash, nil
}

// createTunnelGatewayMessage creates a TunnelGateway message containing a DatabaseStore
// message. This wraps the DatabaseStore for delivery through an outbound tunnel.
func (p *Publisher) createTunnelGatewayMessage(hash common.Hash, data []byte, dataType byte, tunnelID tunnel.TunnelID) (i2np.Message, error) {
	// Create DatabaseStore I2NP message
	dbStoreMsg, err := p.createDatabaseStoreMessage(hash, data, dataType)
	if err != nil {
		return nil, err
	}

	// Marshal DatabaseStore message for tunnel wrapping
	dbStoreMsgBytes, err := dbStoreMsg.MarshalBinary()
	if err != nil {
		return nil, oops.Errorf("failed to marshal DatabaseStore I2NP message: %w", err)
	}

	// Create TunnelGateway message to inject DatabaseStore into outbound tunnel
	tunnelGateway := i2np.NewTunnelGatewayMessage(tunnelID, dbStoreMsgBytes)
	return tunnelGateway, nil
}

// createDatabaseStoreMessage creates a DatabaseStore I2NP message with the provided
// hash, data, and type. The dataType should be one of the DATABASE_STORE_TYPE_* constants:
//   - DatabaseStoreTypeRouterInfo (0): For RouterInfo entries
//   - DatabaseStoreTypeLeaseSet (1): For original LeaseSet entries
//   - DatabaseStoreTypeLeaseSet2 (3): For LeaseSet2 entries (standard as of 0.9.38+)
//   - DatabaseStoreTypeEncryptedLeaseSet (5): For EncryptedLeaseSet entries (0.9.39+)
//   - DatabaseStoreTypeMetaLeaseSet (7): For MetaLeaseSet entries (0.9.40+)
func (p *Publisher) createDatabaseStoreMessage(hash common.Hash, data []byte, dataType byte) (i2np.Message, error) {
	dbStore := i2np.NewDatabaseStore(hash, data, dataType)
	replyToken, err := generateReplyToken()
	if err != nil {
		return nil, oops.Errorf("failed to generate DatabaseStore reply token: %w", err)
	}
	dbStore.ReplyToken = replyToken

	if replyTunnelID, replyGateway, ok := p.selectReplyRoute(); ok {
		dbStore.ReplyTunnelID = replyTunnelID
		dbStore.ReplyGateway = replyGateway
	}
	return dbStore, nil
}

// selectReplyRoute returns a reply tunnel ID and gateway hash for DatabaseStore acks.
//
// ReplyGateway must identify the inbound tunnel gateway router (IBGW), not our
// local router hash, because the sender targets the gateway that owns the
// ReplyTunnelID path.
//
// Returns ok=false when no valid inbound reply route is available.
func (p *Publisher) selectReplyRoute() ([4]byte, common.Hash, bool) {
	p.fieldMu.RLock()
	inboundPool := p.inboundPool
	p.fieldMu.RUnlock()

	if inboundPool == nil {
		return [4]byte{}, common.Hash{}, false
	}

	inbound := inboundPool.SelectTunnel()
	if inbound == nil {
		return [4]byte{}, common.Hash{}, false
	}
	if len(inbound.Hops) == 0 {
		return [4]byte{}, common.Hash{}, false
	}

	var replyTunnelID [4]byte
	binary.BigEndian.PutUint32(replyTunnelID[:], uint32(inbound.ID))
	return replyTunnelID, inbound.Hops[0], true
}

// generateReplyToken returns a cryptographically random non-zero DatabaseStore reply token.
// Floodfills use a non-zero token to decide whether to flood the store entry.
func generateReplyToken() ([4]byte, error) {
	var token [4]byte
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := crand.Read(token[:]); err != nil {
			return [4]byte{}, err
		}
		if token != ([4]byte{}) {
			return token, nil
		}
	}

	// Extremely unlikely fallback: preserve non-zero invariant even if RNG repeatedly returns all-zero bytes.
	token[3] = 1
	return token, nil
}

// sendMessageThroughGateway sends an I2NP message to a gateway router via transport.
// This retrieves the gateway RouterInfo, establishes a transport session, and queues
// the message for transmission.
func (p *Publisher) sendMessageThroughGateway(gatewayHash common.Hash, msg i2np.Message) error {
	// Get gateway router's RouterInfo from NetDB
	gatewayRouterInfo, err := p.getGatewayRouterInfo(gatewayHash)
	if err != nil {
		return oops.Errorf("failed to get gateway RouterInfo: %w", err)
	}

	// Get or create transport session to gateway router
	p.fieldMu.RLock()
	transport := p.transport
	p.fieldMu.RUnlock()
	if transport == nil {
		return oops.Errorf("transport manager not available")
	}
	session, err := transport.GetSession(*gatewayRouterInfo)
	if err != nil {
		return oops.Errorf("failed to get transport session to gateway: %w", err)
	}

	// Queue message for transmission
	if err := session.QueueSendI2NP(msg); err != nil {
		return oops.Errorf("failed to queue message for transmission: %w", err)
	}
	return nil
}

// getGatewayRouterInfo retrieves the RouterInfo for a gateway router from the NetDB.
// Returns an error if the RouterInfo cannot be retrieved or has no identity.
func (p *Publisher) getGatewayRouterInfo(gatewayHash common.Hash) (*router_info.RouterInfo, error) {
	// Get RouterInfo from NetDB using the hash
	riChan := p.db.GetRouterInfo(gatewayHash)
	if riChan == nil {
		return nil, oops.Errorf("gateway %x not found in NetDB", gatewayHash[:8])
	}
	ri, ok := <-riChan
	if !ok {
		return nil, oops.Errorf("failed to retrieve RouterInfo for gateway %x", gatewayHash[:8])
	}

	// Check if RouterInfo has a valid identity by verifying we can get its hash.
	// Note: We don't use IsValid() because in test environments, RouterInfo without
	// addresses may be considered invalid even though they have valid identities.
	// For transport purposes, we only need a valid identity to establish a session.
	_, err := ri.IdentHash()
	if err != nil {
		return nil, oops.Errorf("gateway %x not found in NetDB or has no valid identity: %w", gatewayHash[:8], err)
	}

	return &ri, nil
}

// SetTransport sets the transport manager after publisher creation.
// This allows the transport to be configured after initial publisher setup.
func (p *Publisher) SetTransport(transport SessionProvider) {
	p.fieldMu.Lock()
	p.transport = transport
	p.fieldMu.Unlock()
}

// SetLookupTransport configures the direct lookup transport used for
// post-publication RouterInfo retrievability checks.
func (p *Publisher) SetLookupTransport(transport LookupTransport) {
	p.fieldMu.Lock()
	p.lookupTransport = transport
	p.fieldMu.Unlock()
}

// PublishOurRouterInfo triggers an immediate republication of our RouterInfo
// to floodfill routers. Use this when the RouterInfo has changed (e.g. after
// introducer addresses are updated following NAT detection).
func (p *Publisher) PublishOurRouterInfo() {
	p.publishOurRouterInfo()
}

// GetStats returns statistics about publishing activity
func (p *Publisher) GetStats() PublisherStats {
	return PublisherStats{
		RouterInfoInterval:       p.routerInfoInterval,
		LeaseSetInterval:         p.leaseSetInterval,
		FloodfillCount:           p.floodfillCount,
		IsRunning:                p.ctx.Err() == nil,
		RouterInfoPublishSuccess: p.routerInfoPublishSuccess.Load(),
		RouterInfoPublishFail:    p.routerInfoPublishFail.Load(),
		RouterInfoVerifySuccess:  p.routerInfoVerifySuccess.Load(),
		RouterInfoVerifyFail:     p.routerInfoVerifyFail.Load(),
	}
}

// PublisherStats contains statistics about publisher activity
type PublisherStats struct {
	RouterInfoInterval       time.Duration
	LeaseSetInterval         time.Duration
	FloodfillCount           int
	IsRunning                bool
	RouterInfoPublishSuccess uint64
	RouterInfoPublishFail    uint64
	RouterInfoVerifySuccess  uint64
	RouterInfoVerifyFail     uint64
}

// Compile-time interface check
var _ interface {
	Start() error
	Stop()
	PublishLeaseSet(hash common.Hash, leaseSetData []byte) error
	PublishRouterInfo(ri router_info.RouterInfo) error
} = (*Publisher)(nil)
