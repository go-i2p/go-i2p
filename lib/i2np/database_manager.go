package i2np

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// DatabaseManager coordinates database-related message processing and response generation.
type DatabaseManager struct {
	netdb             I2NPNetDBStore
	retriever         NetDBRetriever
	floodfillSelector FloodfillSelector
	sessionProvider   SessionProvider
	factory           *I2NPMessageFactory
	ourRouterHash     common.Hash // Our router's identity hash for DatabaseSearchReply

	// Rate limiting for DatabaseLookup messages
	lookupLimiter struct {
		mu      sync.Mutex
		lookups map[common.Hash]time.Time // Track lookup frequency by source hash
	}
}

// I2NPNetDBStore defines the interface for storing network database entries.
// Implementations must dispatch to the appropriate storage method based on dataType:
//   - 0: RouterInfo
//   - 1: LeaseSet
//   - 3: LeaseSet2
//   - 5: EncryptedLeaseSet
//   - 7: MetaLeaseSet
type I2NPNetDBStore interface {
	Store(key common.Hash, data []byte, dataType byte) error
}

// I2NPNetDBStoreWithSource extends I2NPNetDBStore with source-peer context.
// Implementations can use this for fairness/rate controls on first-seen entries.
type I2NPNetDBStoreWithSource interface {
	StoreFromPeer(key common.Hash, data []byte, dataType byte, source common.Hash) error
}

// NetDBRetriever defines the interface for retrieving RouterInfo entries
type NetDBRetriever interface {
	GetRouterInfoBytes(hash common.Hash) ([]byte, error)
	GetRouterInfoCount() int
}

// FloodfillSelector defines the interface for selecting closest floodfill routers
type FloodfillSelector interface {
	SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error)
}

// I2NPTransportSession defines the interface for sending I2NP messages back to requesters
type I2NPTransportSession interface {
	QueueSendI2NP(msg I2NPMessage) error
	SendQueueSize() int
}

// SessionProvider defines the interface for obtaining transport sessions
type SessionProvider interface {
	GetSessionByHash(hash common.Hash) (I2NPTransportSession, error)
}

// NewDatabaseManager creates a new database manager with NetDB integration
func NewDatabaseManager(netdb I2NPNetDBStore) *DatabaseManager {
	dm := &DatabaseManager{
		netdb:             netdb,
		retriever:         nil, // Will be set later via SetRetriever
		floodfillSelector: nil, // Will be set later via SetFloodfillSelector
		sessionProvider:   nil, // Will be set later via SetSessionProvider
		factory:           NewI2NPMessageFactory(),
	}
	dm.lookupLimiter.lookups = make(map[common.Hash]time.Time)
	return dm
}

// SetRetriever sets the NetDB retriever for database operations
func (dm *DatabaseManager) SetRetriever(retriever NetDBRetriever) {
	dm.retriever = retriever
}

// SetFloodfillSelector sets the floodfill selector for selecting closest floodfill routers
func (dm *DatabaseManager) SetFloodfillSelector(selector FloodfillSelector) {
	dm.floodfillSelector = selector
}

// SetOurRouterHash sets our router's identity hash for use in DatabaseSearchReply messages
func (dm *DatabaseManager) SetOurRouterHash(hash common.Hash) {
	dm.ourRouterHash = hash
}

// SetSessionProvider sets the session provider for sending responses
func (dm *DatabaseManager) SetSessionProvider(provider SessionProvider) {
	dm.sessionProvider = provider
}

// PerformLookup performs a database lookup using DatabaseReader interface and generates appropriate responses
func (dm *DatabaseManager) PerformLookup(reader DatabaseReader) error {
	// Check rate limit before processing
	from := reader.GetFrom()
	if !dm.rateLimitLookup(from) {
		log.WithField("from", fmt.Sprintf("%x", from[:8])).Warn("DatabaseLookup rate limited")
		return oops.Errorf("lookup rate limit exceeded")
	}

	dm.logLookupRequest(reader)

	if dm.sessionProvider == nil {
		return dm.handleLookupWithoutSession(reader.GetKey())
	}

	return dm.performLookupWithSession(reader.GetKey(), reader.GetFrom())
}

// rateLimitLookup enforces rate limits on DatabaseLookup messages by source.
// Returns true if the lookup is allowed, false if rate limited.
func (dm *DatabaseManager) rateLimitLookup(from common.Hash) bool {
	const (
		minLookupInterval = 100 * time.Millisecond // Minimum 100ms between lookups from same source
		maxTrackedSources = 1000                   // Maximum number of sources to track
		cleanupAge        = 5 * time.Minute        // Clean entries older than 5 minutes
	)

	dm.lookupLimiter.mu.Lock()
	defer dm.lookupLimiter.mu.Unlock()

	lastLookup, exists := dm.lookupLimiter.lookups[from]
	now := time.Now()

	if exists && now.Sub(lastLookup) < minLookupInterval {
		return false // Rate limited
	}

	dm.lookupLimiter.lookups[from] = now

	// Periodically clean old entries to prevent unbounded growth
	if len(dm.lookupLimiter.lookups) > maxTrackedSources {
		for hash, ts := range dm.lookupLimiter.lookups {
			if now.Sub(ts) > cleanupAge {
				delete(dm.lookupLimiter.lookups, hash)
			}
		}
	}

	return true
}

// logLookupRequest logs the incoming database lookup request details.
func (dm *DatabaseManager) logLookupRequest(reader DatabaseReader) {
	key := reader.GetKey()
	from := reader.GetFrom()
	log.WithFields(logger.Fields{
		"key":   fmt.Sprintf("%x", key[:8]),
		"from":  fmt.Sprintf("%x", from[:8]),
		"flags": reader.GetFlags(),
	}).Debug("Performing database lookup")
}

// handleLookupWithoutSession performs lookup without sending responses for backward compatibility.
func (dm *DatabaseManager) handleLookupWithoutSession(key common.Hash) error {
	log.WithFields(logger.Fields{"at": "handleLookupWithoutSession"}).Debug("No session provider available, performing lookup without sending response")

	if dm.retriever == nil {
		log.WithFields(logger.Fields{"at": "handleLookupWithoutSession"}).Debug("No retriever available, cannot perform lookup")
		return nil
	}

	if data, err := dm.retrieveRouterInfo(key); err == nil {
		log.WithField("data_size", len(data)).Debug("RouterInfo found locally")
	} else {
		log.WithField("error", err).Debug("RouterInfo not found locally")
	}
	return nil
}

// performLookupWithSession attempts lookup and sends appropriate response message.
func (dm *DatabaseManager) performLookupWithSession(key, from common.Hash) error {
	if dm.retriever == nil {
		log.WithFields(logger.Fields{"at": "performLookupWithSession"}).Debug("No retriever available, cannot perform lookup")
		return dm.sendDatabaseSearchReply(key, from)
	}

	data, err := dm.retrieveRouterInfo(key)
	if err == nil {
		return dm.sendDatabaseStoreResponse(key, data, from)
	}

	log.WithField("error", err).Debug("RouterInfo not found locally for remote lookup")
	return dm.sendDatabaseSearchReply(key, from)
}

// retrieveRouterInfo attempts to retrieve RouterInfo data from the NetDB
func (dm *DatabaseManager) retrieveRouterInfo(key common.Hash) ([]byte, error) {
	data, err := dm.retriever.GetRouterInfoBytes(key)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to retrieve RouterInfo")
	}
	if len(data) == 0 {
		return nil, oops.Errorf("RouterInfo not found for key %x", key[:8])
	}
	return data, nil
}

// sendDatabaseStoreResponse sends a DatabaseStore message back to the requester
func (dm *DatabaseManager) sendDatabaseStoreResponse(key common.Hash, data []byte, to common.Hash) error {
	// Create DatabaseStore message with the found RouterInfo
	response := NewDatabaseStore(key, data, 0) // RouterInfo type is 0
	return dm.sendResponse(response, to)
}

// sendDatabaseSearchReply sends a DatabaseSearchReply when RouterInfo is not found.
// This implements floodfill router functionality by selecting and suggesting the closest
// floodfill routers to the target hash using Kademlia XOR distance metric.
//
// Per I2P specification, when acting as a floodfill router:
// 1. If the requested key is not in our NetDB
// 2. We respond with a DatabaseSearchReply containing hashes of other floodfill routers
// 3. These routers are selected as the closest to the target key by XOR distance
// 4. Typically 3-7 peer hashes are included to help the requester continue their search
func (dm *DatabaseManager) sendDatabaseSearchReply(key, to common.Hash) error {
	// Select closest floodfill routers to suggest
	peerHashes := dm.selectClosestFloodfills(key)

	// Create DatabaseSearchReply with our router hash and suggested peers
	response := NewDatabaseSearchReply(key, dm.ourRouterHash, peerHashes)

	dm.logDatabaseSearchReply(key, to, len(peerHashes))
	return dm.sendResponse(response, to)
}

// selectClosestFloodfills selects the closest floodfill routers to suggest for a lookup.
// Returns up to 7 peer hashes (standard I2P practice) sorted by XOR distance to target.
// If no floodfill selector is configured, returns empty list for backward compatibility.
func (dm *DatabaseManager) selectClosestFloodfills(targetKey common.Hash) []common.Hash {
	const defaultFloodfillCount = 7 // I2P standard practice

	if !dm.hasFloodfillSelector() {
		return []common.Hash{}
	}

	floodfills, err := dm.fetchFloodfillRouters(targetKey, defaultFloodfillCount)
	if err != nil || len(floodfills) == 0 {
		return []common.Hash{}
	}

	return dm.convertRoutersToHashes(floodfills)
}

// hasFloodfillSelector checks if a floodfill selector is configured.
func (dm *DatabaseManager) hasFloodfillSelector() bool {
	if dm.floodfillSelector == nil {
		log.WithFields(logger.Fields{"at": "hasFloodfillSelector"}).Debug("No floodfill selector available, returning empty peer list")
		return false
	}
	return true
}

// fetchFloodfillRouters retrieves floodfill routers for the target key.
func (dm *DatabaseManager) fetchFloodfillRouters(targetKey common.Hash, count int) ([]router_info.RouterInfo, error) {
	floodfills, err := dm.floodfillSelector.SelectFloodfillRouters(targetKey, count)
	if err != nil {
		log.WithError(err).Warn("Failed to select floodfill routers for DatabaseSearchReply")
		return nil, err
	}

	if len(floodfills) == 0 {
		log.WithFields(logger.Fields{"at": "fetchFloodfillRouters"}).Debug("No floodfill routers available for peer suggestions")
	}

	return floodfills, nil
}

// convertRoutersToHashes converts RouterInfo list to hash list, skipping invalid entries.
func (dm *DatabaseManager) convertRoutersToHashes(floodfills []router_info.RouterInfo) []common.Hash {
	peerHashes := make([]common.Hash, 0, len(floodfills))

	for _, ri := range floodfills {
		if hash := dm.extractValidHash(ri); !dm.isEmptyHash(hash) {
			peerHashes = append(peerHashes, hash)
		}
	}

	return peerHashes
}

// extractValidHash extracts identity hash from RouterInfo, returning empty hash on error.
func (dm *DatabaseManager) extractValidHash(ri router_info.RouterInfo) common.Hash {
	hash, err := ri.IdentHash()
	if err != nil {
		log.WithError(err).Debug("Skipping invalid RouterInfo in floodfill selection")
		return common.Hash{}
	}
	return hash
}

// isEmptyHash checks if a hash is the zero value.
func (dm *DatabaseManager) isEmptyHash(hash common.Hash) bool {
	var emptyHash common.Hash
	return hash == emptyHash
}

// logDatabaseSearchReply logs details about the DatabaseSearchReply being sent.
func (dm *DatabaseManager) logDatabaseSearchReply(key, to common.Hash, peerCount int) {
	log.WithFields(logger.Fields{
		"target_key":      fmt.Sprintf("%x", key[:8]),
		"destination":     fmt.Sprintf("%x", to[:8]),
		"suggested_peers": peerCount,
		"our_router_hash": fmt.Sprintf("%x", dm.ourRouterHash[:8]),
	}).Debug("Sending DatabaseSearchReply with floodfill peer suggestions")
}

// sendResponse sends an I2NP message response using the session provider
func (dm *DatabaseManager) sendResponse(response interface{}, to common.Hash) error {
	if dm.sessionProvider == nil {
		return oops.Errorf("no session provider available for sending response")
	}

	session, err := dm.sessionProvider.GetSessionByHash(to)
	if err != nil {
		return oops.Wrapf(err, "failed to get session for %x", to[:8])
	}

	// Convert response to I2NPMessage interface
	var msg I2NPMessage
	switch r := response.(type) {
	case *DatabaseStore:
		msg = dm.createDatabaseStoreMessage(r)
	case *DatabaseSearchReply:
		msg = dm.createDatabaseSearchReplyMessage(r)
	default:
		return oops.Errorf("unsupported response type: %T", response)
	}

	// Check if message creation failed
	if msg == nil {
		return oops.Errorf("failed to create response message for %x", to[:8])
	}

	// Send the response
	if err := session.QueueSendI2NP(msg); err != nil {
		return oops.Wrapf(err, "failed to queue response message for %x", to[:8])
	}
	log.WithFields(logger.Fields{
		"message_type": msg.Type(),
		"destination":  fmt.Sprintf("%x", to[:8]),
	}).Debug("Queued response message")
	return nil
}

// createDatabaseStoreMessage creates an I2NP message from DatabaseStore.
// Uses MarshalPayload (payload-only serialization) rather than MarshalBinary
// (full I2NP message) because this function creates its own BaseI2NPMessage
// wrapper. This also avoids a panic when the store's embedded BaseI2NPMessage
// is nil (e.g., from deserialized/corrupted data).
func (dm *DatabaseManager) createDatabaseStoreMessage(store *DatabaseStore) I2NPMessage {
	msg := NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore)
	data, err := store.MarshalPayload()
	if err != nil {
		log.WithField("error", err).Error("Failed to marshal DatabaseStore payload")
		return nil
	}
	msg.SetData(data)
	return msg
}

// createDatabaseSearchReplyMessage creates an I2NP message from DatabaseSearchReply.
// Uses MarshalPayload (payload-only serialization) rather than MarshalBinary
// to avoid a panic when the reply's embedded BaseI2NPMessage is nil.
func (dm *DatabaseManager) createDatabaseSearchReplyMessage(reply *DatabaseSearchReply) I2NPMessage {
	msg := NewBaseI2NPMessage(I2NPMessageTypeDatabaseSearchReply)
	data, err := reply.MarshalPayload()
	if err != nil {
		log.WithField("error", err).Error("Failed to marshal DatabaseSearchReply payload")
		return nil
	}
	msg.SetData(data)
	return msg
}

// validateGzipSize validates gzip compressed data to prevent decompression bombs.
// It checks that the uncompressed size doesn't exceed maxUncompressed and that
// the compression ratio doesn't exceed maxRatio.
// Returns the uncompressed size and an error if validation fails.
func validateGzipSize(data []byte, maxUncompressed, maxRatio int) (int, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return 0, oops.Wrapf(err, "invalid gzip data")
	}
	defer func() { _ = gr.Close() }()

	// Use limited reader to prevent full decompression of malicious data
	lr := &io.LimitedReader{R: gr, N: int64(maxUncompressed + 1)}
	n, _ := io.Copy(io.Discard, lr)

	if n > int64(maxUncompressed) {
		return int(n), oops.Errorf("uncompressed size exceeds limit (%d > %d)", n, maxUncompressed)
	}

	ratio := float64(n) / float64(len(data))
	if ratio > float64(maxRatio) {
		return int(n), oops.Errorf("compression ratio too high (%.2f:1 > %d:1)", ratio, maxRatio)
	}

	return int(n), nil
}

// StoreData stores data using DatabaseWriter interface and NetDB integration
func (dm *DatabaseManager) StoreData(writer DatabaseWriter) error {
	return dm.storeDataInternal(writer, nil)
}

// StoreDataFromPeer stores data with source peer context when available.
func (dm *DatabaseManager) StoreDataFromPeer(writer DatabaseWriter, source common.Hash) error {
	return dm.storeDataInternal(writer, &source)
}

func (dm *DatabaseManager) storeDataInternal(writer DatabaseWriter, source *common.Hash) error {
	key := writer.GetStoreKey()
	data := writer.GetStoreData()
	dataType := writer.GetStoreType()

	// Validate data before storing
	if err := validateStoreData(data, dataType); err != nil {
		return err
	}

	log.WithFields(logger.Fields{
		"data_size": len(data),
		"data_type": dataType,
		"key":       fmt.Sprintf("%x", key[:8]),
	}).Debug("Storing data in NetDB")

	if dm.netdb != nil {
		if source != nil {
			if withSource, ok := dm.netdb.(I2NPNetDBStoreWithSource); ok {
				return withSource.StoreFromPeer(key, data, dataType, *source)
			}
		}
		return dm.netdb.Store(key, data, dataType)
	}

	return oops.Errorf("no NetDB available for storage")
}

// validateStoreData validates data size and compression before storing.
func validateStoreData(data []byte, dataType byte) error {
	// I2P spec: RouterInfo is gzip-compressed, typical size 1-2 KB compressed, 3-10 KB uncompressed
	const (
		MaxCompressedSize   = 20 * 1024  // 20 KB compressed (generous limit)
		MaxUncompressedSize = 100 * 1024 // 100 KB uncompressed (generous limit)
		MaxCompressionRatio = 100        // Detect decompression bombs
	)

	// Validate data size before processing to prevent resource exhaustion
	if len(data) > MaxCompressedSize {
		log.WithFields(logger.Fields{
			"data_size": len(data),
			"max_size":  MaxCompressedSize,
		}).Warn("Rejecting oversized database store data")
		return oops.Errorf("database store data too large: %d bytes (max %d)", len(data), MaxCompressedSize)
	}

	// For RouterInfo (type 0), validate compression if data appears compressed
	if dataType == DatabaseStoreTypeRouterInfo && len(data) > 2 {
		return validateRouterInfoCompression(data, MaxUncompressedSize, MaxCompressionRatio)
	}

	return nil
}

// validateRouterInfoCompression checks gzip-compressed RouterInfo for decompression bombs.
func validateRouterInfoCompression(data []byte, maxUncompressed, maxRatio int) error {
	// Check if data starts with gzip magic number (0x1f 0x8b)
	if data[0] != 0x1f || data[1] != 0x8b {
		return nil // Not gzip-compressed, skip validation
	}

	// Validate decompression bomb risk before processing
	uncompressedSize, err := validateGzipSize(data, maxUncompressed, maxRatio)
	if err != nil {
		log.WithFields(logger.Fields{
			"compressed_size":   len(data),
			"uncompressed_size": uncompressedSize,
			"error":             err,
		}).Warn("Rejecting suspicious compressed RouterInfo")
		return oops.Wrapf(err, "invalid compressed RouterInfo")
	}

	log.WithFields(logger.Fields{
		"compressed_size":   len(data),
		"uncompressed_size": uncompressedSize,
	}).Debug("Validated gzip-compressed RouterInfo")

	return nil
}
