package netdb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/base64"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/netdb/reseed"
)

// standard network database implementation using local filesystem skiplist
type StdNetDB struct {
	DB          string
	RouterInfos map[common.Hash]Entry
	riMutex     sync.RWMutex // mutex for RouterInfos (RWMutex for read-heavy operations)
	LeaseSets   map[common.Hash]Entry
	lsMutex     sync.RWMutex // mutex for LeaseSets (RWMutex for read-heavy operations)

	// Expiration tracking for LeaseSets
	leaseSetExpiry map[common.Hash]time.Time // maps hash to expiration time

	// Expiration tracking for RouterInfos (based on published date + RouterInfoMaxAge)
	routerInfoExpiry map[common.Hash]time.Time // maps hash to expiration time

	expiryMutex sync.RWMutex // mutex for expiry tracking (shared for both LeaseSets and RouterInfos)

	PeerTracker *PeerTracker // tracks connection success/failure for peers

	// riRefreshCooldown stores the time of the last RequestRouterInfoRefresh
	// call per peer hash to prevent thundering-herd re-fetches.
	riRefreshCooldown sync.Map // map[common.Hash]time.Time

	// Cleanup goroutine management
	ctx       context.Context
	cancel    context.CancelFunc
	cleanupWg sync.WaitGroup
}

// NewStdNetDB creates and returns a new StdNetDB rooted at the given directory path,
// initializing in-memory caches and starting the background expiration cleaner.
func NewStdNetDB(db string) *StdNetDB {
	log.WithFields(logger.Fields{
		"at":      "(StdNetDB) NewStdNetDB",
		"reason":  "initializing network database",
		"db_path": db,
	}).Debug("creating new StdNetDB")
	ctx, cancel := context.WithCancel(context.Background())
	ndb := &StdNetDB{
		DB:               db,
		RouterInfos:      make(map[common.Hash]Entry),
		riMutex:          sync.RWMutex{},
		LeaseSets:        make(map[common.Hash]Entry),
		lsMutex:          sync.RWMutex{},
		leaseSetExpiry:   make(map[common.Hash]time.Time),
		routerInfoExpiry: make(map[common.Hash]time.Time),
		expiryMutex:      sync.RWMutex{},
		PeerTracker:      NewPeerTracker(),
		ctx:              ctx,
		cancel:           cancel,
	}
	ndb.StartExpirationCleaner()
	return ndb
}

// GetRouterInfo returns a channel that yields the RouterInfo for the given hash,
// checking the in-memory cache first and falling back to disk.
func (db *StdNetDB) GetRouterInfo(hash common.Hash) (chnl chan router_info.RouterInfo) {
	log.WithFields(logger.Fields{
		"at":     "(StdNetDB) GetRouterInfo",
		"reason": "looking up router info",
		"hash":   fmt.Sprintf("%x...", hash[:8]),
	}).Debug("getting RouterInfo")

	// Check memory cache first
	db.riMutex.RLock()
	if ri, ok := db.RouterInfos[hash]; ok && ri.RouterInfo != nil {
		db.riMutex.RUnlock()
		log.WithFields(logger.Fields{
			"at":     "(StdNetDB) GetRouterInfo",
			"reason": "cache hit",
			"hash":   fmt.Sprintf("%x...", hash[:8]),
		}).Debug("routerInfo found in memory cache")
		chnl = make(chan router_info.RouterInfo, 1)
		chnl <- *ri.RouterInfo
		close(chnl)
		return chnl
	}
	db.riMutex.RUnlock()

	// Load from file
	data, err := db.loadRouterInfoFromFile(hash)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(StdNetDB) GetRouterInfo",
			"reason": "file load failed",
			"hash":   fmt.Sprintf("%x...", hash[:8]),
		}).Error("failed to load RouterInfo from file")
		// Return a closed empty channel instead of nil so that callers
		// doing <-chnl receive the zero value immediately rather than
		// blocking forever on a nil channel.
		chnl = make(chan router_info.RouterInfo)
		close(chnl)
		return chnl
	}

	chnl = make(chan router_info.RouterInfo, 1)
	ri, err := db.parseAndCacheRouterInfo(hash, data)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(StdNetDB) GetRouterInfo",
			"reason": "parse failed",
			"hash":   fmt.Sprintf("%x...", hash[:8]),
		}).Error("failed to parse RouterInfo")
		close(chnl)
		return chnl
	}

	chnl <- ri
	close(chnl)
	return chnl
}

// loadRouterInfoFromFile loads RouterInfo data from the skiplist file.
// loadRouterInfoFromFile loads a RouterInfo from the skiplist file,
// stripping the entry framing (1-byte type code + 2-byte length prefix)
// that was written by Entry.WriteTo. Returns the unframed payload data.
func (db *StdNetDB) loadRouterInfoFromFile(hash common.Hash) ([]byte, error) {
	fname := db.SkiplistFile(hash)

	f, err := os.Open(fname)
	if err != nil {
		return nil, oops.Errorf("failed to open RouterInfo file: %w", err)
	}
	defer f.Close()

	entry := &Entry{}
	if err := entry.Deserialize(f); err != nil {
		return nil, oops.Errorf("failed to read RouterInfo entry: %w", err)
	}

	return db.serializeEntry(entry)
}

// parseAndCacheRouterInfo parses RouterInfo data and adds it to the memory cache.
// If a cached entry already exists, the new entry replaces it only if it has a
// newer published timestamp, matching the behavior of addRouterInfoToCache.
func (db *StdNetDB) parseAndCacheRouterInfo(hash common.Hash, data []byte) (router_info.RouterInfo, error) {
	ri, _, err := router_info.ReadRouterInfo(data)
	if err != nil {
		return router_info.RouterInfo{}, oops.Errorf("failed to parse RouterInfo: %w", err)
	}

	// Add to cache, or replace if newer
	db.riMutex.Lock()
	if existing, ok := db.RouterInfos[hash]; ok {
		// Compare timestamps: only replace if the new entry is strictly newer
		if existing.RouterInfo != nil {
			existPub := existing.RouterInfo.Published()
			newPub := ri.Published()
			if existPub != nil && newPub != nil && !newPub.Time().After(existPub.Time()) {
				db.riMutex.Unlock()
				log.WithFields(logger.Fields{
					"at":     "StdNetDB.parseAndCacheRouterInfo",
					"reason": "existing_entry_same_or_newer",
				}).Debug("skipping RouterInfo update — cached version is same or newer")
				return ri, nil
			}
		}
		log.WithFields(logger.Fields{
			"at":     "StdNetDB.parseAndCacheRouterInfo",
			"reason": "replacing_stale_entry",
		}).Debug("replacing stale RouterInfo in memory cache")
	} else {
		log.WithFields(logger.Fields{
			"at":     "StdNetDB.parseAndCacheRouterInfo",
			"reason": "new_entry",
		}).Debug("adding RouterInfo to memory cache")
	}
	db.RouterInfos[hash] = Entry{
		RouterInfo: &ri,
	}
	db.riMutex.Unlock()

	return ri, nil
}

// get the skiplist file that a RouterInfo with this hash would go in
func (db *StdNetDB) SkiplistFile(hash common.Hash) (fpath string) {
	fname := base64.EncodeToString(hash[:])
	fpath = filepath.Join(db.Path(), fmt.Sprintf("r%c", fname[0]), fmt.Sprintf("routerInfo-%s.dat", fname))
	log.WithField("file_path", fpath).Debug("Generated skiplist file path")
	return fpath
}

// get netdb path
func (db *StdNetDB) Path() string {
	return string(db.DB)
}

// Size returns the count of RouterInfos currently stored in the network database.
// This is a direct in-memory count and does not require filesystem access.
func (db *StdNetDB) Size() (routers int) {
	db.riMutex.RLock()
	routers = len(db.RouterInfos)
	db.riMutex.RUnlock()

	log.WithField("count", routers).Debug("NetDB size calculated from in-memory RouterInfos")
	return routers
}

// CheckFilePathValid reports whether the given file path is a valid NetDB entry path,
// verifying it has the correct extension, resolves within the NetDB directory, and passes security checks.
func (db *StdNetDB) CheckFilePathValid(fpath string) bool {
	if !db.validateFileExtension(fpath) {
		return false
	}

	cleanPath, err := db.resolveAndCleanPath(fpath)
	if err != nil {
		return false
	}

	if !db.verifyPathWithinNetDB(fpath, cleanPath) {
		return false
	}

	if !db.validatePathSecurity(cleanPath) {
		return false
	}

	log.WithFields(logger.Fields{
		"file_path": cleanPath,
		"is_valid":  true,
	}).Debug("File path validation successful")
	return true
}

// validateFileExtension checks if the file has the required .dat extension.
func (db *StdNetDB) validateFileExtension(fpath string) bool {
	if !strings.HasSuffix(fpath, ".dat") {
		log.WithField("file_path", fpath).Debug("Invalid file extension, expected .dat")
		return false
	}
	return true
}

// resolveAndCleanPath resolves the absolute path and cleans it to remove path traversal components.
func (db *StdNetDB) resolveAndCleanPath(fpath string) (string, error) {
	absPath, err := filepath.Abs(fpath)
	if err != nil {
		log.WithFields(logger.Fields{
			"file_path": fpath,
			"error":     err,
		}).Warn("Failed to resolve absolute path")
		return "", err
	}
	cleanPath := filepath.Clean(absPath)
	return cleanPath, nil
}

// verifyPathWithinNetDB ensures the file path is within the NetDB directory to prevent path traversal attacks.
func (db *StdNetDB) verifyPathWithinNetDB(originalPath, cleanPath string) bool {
	netdbPath, err := filepath.Abs(db.Path())
	if err != nil {
		log.WithFields(logger.Fields{
			"netdb_path": db.Path(),
			"error":      err,
		}).Error("Failed to resolve NetDB absolute path")
		return false
	}

	if !strings.HasPrefix(cleanPath, netdbPath+string(filepath.Separator)) &&
		cleanPath != netdbPath {
		log.WithFields(logger.Fields{
			"file_path":  originalPath,
			"clean_path": cleanPath,
			"netdb_path": netdbPath,
		}).Warn("Path traversal attempt detected, file outside NetDB directory")
		return false
	}
	return true
}

// validatePathSecurity checks for security issues including symlinks and file accessibility.
func (db *StdNetDB) validatePathSecurity(cleanPath string) bool {
	fileInfo, err := os.Lstat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.WithField("file_path", cleanPath).Debug("File path valid (file doesn't exist yet)")
			return true
		}
		log.WithFields(logger.Fields{
			"file_path": cleanPath,
			"error":     err,
		}).Debug("Failed to stat file")
		return false
	}

	if fileInfo.Mode()&os.ModeSymlink != 0 {
		log.WithField("file_path", cleanPath).Warn("Symlink detected, rejecting for security")
		return false
	}
	return true
}

// RecalculateSize is maintained for interface compatibility.
// Since Size() now operates directly on in-memory data, this is a no-op.
func (db *StdNetDB) RecalculateSize() error {
	log.WithFields(logger.Fields{"at": "RecalculateSize"}).Debug("RecalculateSize called - Size() now uses in-memory data")
	return nil
}

// return true if the network db directory exists and is writable
func (db *StdNetDB) Exists() bool {
	p := db.Path()
	// check root directory
	_, err := os.Stat(p)
	if err == nil {
		// check subdirectories for skiplist
		for _, c := range base64.I2PEncodeAlphabet {
			if _, err = os.Stat(filepath.Join(p, fmt.Sprintf("r%c", c))); err != nil {
				return false
			}
		}
	}
	return err == nil
}

// SaveEntry persists a single RouterInfo Entry to disk in the NetDB skiplist directory.
func (db *StdNetDB) SaveEntry(e *Entry) (err error) {
	if e.RouterInfo == nil {
		return oops.Errorf("cannot save entry: RouterInfo is nil (only RouterInfo entries can be persisted to the NetDB skiplist)")
	}
	var f io.WriteCloser
	h, err := e.RouterInfo.IdentHash()
	if err != nil {
		return oops.Errorf("failed to get router hash for saving: %w", err)
	}
	log.WithField("hash", h).Debug("Saving NetDB entry")
	// if err == nil {
	f, err = os.OpenFile(db.SkiplistFile(h), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err == nil {
		defer func() {
			if cerr := f.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}()
		err = e.Serialize(f)
		if err == nil {
			log.WithFields(logger.Fields{"at": "SaveEntry"}).Debug("Successfully saved NetDB entry")
		} else {
			log.WithError(err).Error("Failed to write NetDB entry")
		}
	} else {
		log.WithError(err).Error("Failed to open file for saving NetDB entry")
	}
	//}
	/*
		if err != nil {
			log.Errorf("failed to save netdb entry: %s", err.Error())
		}
	*/
	return err
}

// Save persists all in-memory RouterInfo and LeaseSet entries to disk.
func (db *StdNetDB) Save() error {
	log.WithFields(logger.Fields{"at": "Save"}).Debug("Saving all NetDB entries")

	riErrs := db.saveAllRouterInfos()
	lsErrs := db.saveAllLeaseSets()

	return errors.Join(append(riErrs, lsErrs...)...)
}

// saveAllRouterInfos copies RouterInfo entries under a read lock, then persists each to disk.
// Returns a slice of errors from any failed saves.
func (db *StdNetDB) saveAllRouterInfos() []error {
	db.riMutex.RLock()
	entriesToSave := make([]Entry, 0, len(db.RouterInfos))
	for _, entry := range db.RouterInfos {
		if entry.RouterInfo != nil {
			entriesToSave = append(entriesToSave, entry)
		}
	}
	db.riMutex.RUnlock()

	var errs []error
	for _, entry := range entriesToSave {
		if e := db.SaveEntry(&entry); e != nil {
			errs = append(errs, e)
			log.WithError(e).Error("Failed to save NetDB entry")
		}
	}
	return errs
}

// saveAllLeaseSets copies LeaseSet entries under a read lock, then persists each to disk.
// Returns a slice of errors from any failed saves.
func (db *StdNetDB) saveAllLeaseSets() []error {
	type lsEntry struct {
		hash  common.Hash
		entry Entry
	}

	db.lsMutex.RLock()
	lsEntries := make([]lsEntry, 0, len(db.LeaseSets))
	for h, entry := range db.LeaseSets {
		lsEntries = append(lsEntries, lsEntry{hash: h, entry: entry})
	}
	db.lsMutex.RUnlock()

	var errs []error
	for _, ls := range lsEntries {
		if err := db.saveLeaseSetEntry(ls.hash, ls.entry); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// saveLeaseSetEntry persists a single LeaseSet entry to the filesystem.
func (db *StdNetDB) saveLeaseSetEntry(hash common.Hash, entry Entry) (err error) {
	fpath := db.SkiplistFileForLeaseSet(hash)
	f, ferr := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if ferr != nil {
		log.WithError(ferr).WithField("hash", hash).Error("Failed to open file for saving LeaseSet entry")
		return ferr
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if werr := entry.Serialize(f); werr != nil {
		log.WithError(werr).WithField("hash", hash).Error("Failed to write LeaseSet entry")
		return werr
	}
	return nil
}

// reseed if we have less than minRouters known routers
// returns error if reseed failed
func (db *StdNetDB) Reseed(b bootstrap.Bootstrap, minRouters int) (err error) {
	if !db.isReseedRequired(minRouters) {
		return nil
	}

	peers, err := db.retrievePeersFromBootstrap(b)
	if err != nil {
		return err
	}

	count := db.addNewRouterInfos(peers)
	log.WithField("added_routers", count).Info("Reseed completed successfully")

	return db.updateCacheAfterReseed()
}

// isReseedRequired checks if reseed is necessary based on current database size.
func (db *StdNetDB) isReseedRequired(minRouters int) bool {
	log.WithField("min_routers", minRouters).Debug("Checking if reseed is necessary")
	if db.Size() > minRouters {
		log.WithFields(logger.Fields{"at": "isReseedRequired"}).Debug("Reseed not necessary")
		return false
	}
	log.WithFields(logger.Fields{"at": "isReseedRequired"}).Warn("NetDB size below minimum, reseed required")
	return true
}

// retrievePeersFromBootstrap gets peers from the bootstrap provider with timeout.
func (db *StdNetDB) retrievePeersFromBootstrap(b bootstrap.Bootstrap) ([]router_info.RouterInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), reseed.DefaultDialTimeout)
	defer cancel()

	peersChan, err := b.GetPeers(ctx, 0) // Get as many peers as possible
	if err != nil {
		log.WithError(err).Error("Failed to get peers from bootstrap provider")
		return nil, oops.Errorf("bootstrap failed: %w", err)
	}

	return peersChan, nil
}

// verifiedRouterEntry holds a RouterInfo that has passed signature and timestamp validation.
type verifiedRouterEntry struct {
	hash common.Hash
	ri   router_info.RouterInfo
}

// addNewRouterInfos processes and adds new RouterInfos from peers to the database.
func (db *StdNetDB) addNewRouterInfos(peers []router_info.RouterInfo) int {
	verified := db.verifyRouterInfoBatch(peers)

	count := db.insertVerifiedRouterInfos(verified)
	return count
}

// verifyRouterInfoBatch validates signatures and timestamps for a batch of RouterInfos.
// Returns only the entries that pass all checks.
func (db *StdNetDB) verifyRouterInfoBatch(peers []router_info.RouterInfo) []verifiedRouterEntry {
	verified := make([]verifiedRouterEntry, 0, len(peers))
	now := time.Now()
	for _, ri := range peers {
		entry, ok := db.validateSingleRouterInfo(ri, now)
		if ok {
			verified = append(verified, entry)
		}
	}
	return verified
}

// validateSingleRouterInfo checks a RouterInfo's hash, signature, and published timestamp.
// Returns the verified entry and true if valid, or a zero entry and false otherwise.
func (db *StdNetDB) validateSingleRouterInfo(ri router_info.RouterInfo, now time.Time) (verifiedRouterEntry, bool) {
	hash, err := ri.IdentHash()
	if err != nil {
		log.WithError(err).Warn("Failed to get router hash during reseed, skipping")
		return verifiedRouterEntry{}, false
	}
	if err := verifyRouterInfoSignature(ri); err != nil {
		log.WithFields(logger.Fields{
			"hash":  hash,
			"error": err.Error(),
		}).Warn("Rejecting RouterInfo from reseed: invalid signature")
		return verifiedRouterEntry{}, false
	}
	if err := db.validatePublishedTimestamp(ri, hash, now); err != nil {
		return verifiedRouterEntry{}, false
	}
	return verifiedRouterEntry{hash: hash, ri: ri}, true
}

// validatePublishedTimestamp rejects RouterInfos with missing, stale, or future-dated timestamps.
func (db *StdNetDB) validatePublishedTimestamp(ri router_info.RouterInfo, hash common.Hash, now time.Time) error {
	published := ri.Published()
	if published == nil || published.Time().IsZero() {
		log.WithField("hash", hash).Warn("Rejecting RouterInfo from reseed: missing published date")
		return oops.Errorf("missing published date")
	}
	if now.Sub(published.Time()) > RouterInfoMaxAge {
		log.WithFields(logger.Fields{
			"hash": hash,
			"age":  now.Sub(published.Time()).Round(time.Second),
		}).Warn("Rejecting RouterInfo from reseed: stale published date")
		return oops.Errorf("stale published date")
	}
	if published.Time().After(now.Add(1 * time.Hour)) {
		log.WithFields(logger.Fields{
			"hash":      hash,
			"published": published.Time(),
		}).Warn("Rejecting RouterInfo from reseed: future-dated published time")
		return oops.Errorf("future-dated published time")
	}
	return nil
}

// insertVerifiedRouterInfos adds verified RouterInfos to the map under the write lock.
// Only inserts entries not already present. Returns the count of newly added entries.
func (db *StdNetDB) insertVerifiedRouterInfos(verified []verifiedRouterEntry) int {
	count := 0
	db.riMutex.Lock()
	for _, entry := range verified {
		if _, exists := db.RouterInfos[entry.hash]; !exists {
			log.WithField("hash", entry.hash).Debug("Adding new RouterInfo from reseed")
			ri := entry.ri
			db.RouterInfos[entry.hash] = Entry{
				RouterInfo: &ri,
			}
			count++
		}
	}
	db.riMutex.Unlock()
	return count
}

// updateCacheAfterReseed updates the size cache after successful reseed operation.
func (db *StdNetDB) updateCacheAfterReseed() error {
	err := db.RecalculateSize()
	if err != nil {
		log.WithError(err).Warn("Failed to update NetDB size cache after reseed")
	}
	return nil
}

// validateRouterInfoDataType checks if the data type is valid for RouterInfo storage.
func validateRouterInfoDataType(dataType byte) error {
	if dataType != 0 {
		log.WithField("type", dataType).Warn("Invalid data type for RouterInfo, expected 0")
		return oops.Errorf("invalid data type for RouterInfo: expected 0, got %d", dataType)
	}
	return nil
}

// parseRouterInfoData parses RouterInfo from raw bytes.
func parseRouterInfoData(data []byte) (router_info.RouterInfo, error) {
	ri, _, err := router_info.ReadRouterInfo(data)
	if err != nil {
		log.WithError(err).Error("Failed to parse RouterInfo from DatabaseStore data")
		return router_info.RouterInfo{}, oops.Errorf("failed to parse RouterInfo: %w", err)
	}
	return ri, nil
}

// verifyRouterInfoHash validates that the provided key matches the RouterInfo identity hash.
func verifyRouterInfoHash(key common.Hash, ri router_info.RouterInfo) error {
	expectedHash, err := ri.IdentHash()
	if err != nil {
		return oops.Errorf("failed to get router hash for verification: %w", err)
	}
	if key != expectedHash {
		log.WithFields(logger.Fields{
			"expected_hash": expectedHash,
			"provided_key":  key,
		}).Error("RouterInfo hash mismatch")
		return oops.Errorf("RouterInfo hash mismatch: expected %x, got %x", expectedHash, key)
	}
	return nil
}

// addRouterInfoToCache adds a RouterInfo entry to the in-memory cache.
// If an entry already exists, it is replaced only if the new RouterInfo
// has a more recent Published timestamp. Returns true if the entry was
// added or updated.
func (db *StdNetDB) addRouterInfoToCache(key common.Hash, ri router_info.RouterInfo) bool {
	db.riMutex.Lock()
	defer db.riMutex.Unlock()

	if existing, exists := db.RouterInfos[key]; exists {
		// Replace only if the new entry is newer.
		if existing.RouterInfo != nil {
			existPub := existing.RouterInfo.Published()
			newPub := ri.Published()
			if existPub != nil && newPub != nil && !newPub.Time().After(existPub.Time()) {
				log.WithField("hash", key).Debug("RouterInfo already exists with same or newer timestamp, skipping")
				return false
			}
		}
		log.WithField("hash", key).Debug("Replacing stale RouterInfo with newer version")
	}

	db.RouterInfos[key] = Entry{
		RouterInfo: &ri,
	}
	return true
}

// persistRouterInfoToFilesystem saves a RouterInfo entry to the filesystem.
// If the save fails, it removes the entry from the in-memory cache.
func (db *StdNetDB) persistRouterInfoToFilesystem(key common.Hash, ri router_info.RouterInfo) error {
	entry := &Entry{
		RouterInfo: &ri,
	}

	if err := db.SaveEntry(entry); err != nil {
		log.WithError(err).Error("Failed to save RouterInfo to filesystem")
		db.riMutex.Lock()
		delete(db.RouterInfos, key)
		db.riMutex.Unlock()
		return oops.Errorf("failed to save RouterInfo to filesystem: %w", err)
	}
	return nil
}

// Store dispatches a DatabaseStore message to the appropriate handler based on data type.
// This implements the NetDBStore interface used by the I2NP message processor.
//   - 0: RouterInfo
//   - 1: LeaseSet
//   - 3: LeaseSet2
//   - 5: EncryptedLeaseSet
//   - 7: MetaLeaseSet
func (db *StdNetDB) Store(key common.Hash, data []byte, dataType byte) error {
	switch dataType {
	case 0:
		return db.StoreRouterInfoFromMessage(key, data, dataType)
	case 1:
		return db.StoreLeaseSet(key, data, dataType)
	case 3:
		return db.StoreLeaseSet2(key, data, dataType)
	case 5:
		return db.StoreEncryptedLeaseSet(key, data, dataType)
	case 7:
		return db.StoreMetaLeaseSet(key, data, dataType)
	default:
		return oops.Errorf("unknown database store type: %d", dataType)
	}
}

// StoreRouterInfoFromMessage stores a RouterInfo entry in the database from I2NP DatabaseStore message.
// It takes the pre-computed identity hash, raw serialized data, and data type byte.
// This is used internally by Store() and by adapters that receive RouterInfo from network messages.
func (db *StdNetDB) StoreRouterInfoFromMessage(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("Storing RouterInfo from DatabaseStore message")

	if err := validateRouterInfoDataType(dataType); err != nil {
		return err
	}

	// DatabaseStore RouterInfo payload is: [2-byte compressed length][gzip data]
	// Must decompress before parsing per I2P spec.
	decompressed, err := decompressRouterInfoPayload(data)
	if err != nil {
		log.WithError(err).Error("Failed to decompress RouterInfo from DatabaseStore")
		return oops.Errorf("failed to decompress RouterInfo: %w", err)
	}

	ri, err := parseRouterInfoData(decompressed)
	if err != nil {
		return err
	}

	if err := verifyRouterInfoHash(key, ri); err != nil {
		return err
	}

	if err := verifyRouterInfoSignature(ri); err != nil {
		return err
	}

	if !db.addRouterInfoToCache(key, ri) {
		return nil
	}

	return db.finalizeRouterInfoStorage(key, ri)
}

// finalizeRouterInfoStorage tracks expiration and persists a cached RouterInfo to disk.
func (db *StdNetDB) finalizeRouterInfoStorage(key common.Hash, ri router_info.RouterInfo) error {
	db.trackRouterInfoPublishedDate(key, ri)

	if err := db.persistRouterInfoToFilesystem(key, ri); err != nil {
		return err
	}

	log.WithField("hash", key).Debug("Successfully stored RouterInfo")
	return nil
}

// trackRouterInfoPublishedDate records the published date for expiration tracking.
func (db *StdNetDB) trackRouterInfoPublishedDate(key common.Hash, ri router_info.RouterInfo) {
	if published := ri.Published(); published != nil && !published.Time().IsZero() {
		db.trackRouterInfoExpiration(key, published.Time())
	}
}

// StoreRouterInfo stores a RouterInfo locally, satisfying the NetworkDatabase interface.
// It computes the identity hash, serializes the RouterInfo, and delegates to StoreRouterInfoFromMessage
// for full validation (hash verification, signature check, caching, and filesystem persistence).
func (db *StdNetDB) StoreRouterInfo(ri router_info.RouterInfo) {
	hash, err := ri.IdentHash()
	if err != nil {
		log.WithError(err).WithField("at", "StdNetDB.StoreRouterInfo").Warn("cannot store RouterInfo without identity hash")
		return
	}
	data, err := ri.Bytes()
	if err != nil {
		log.WithError(err).WithField("at", "StdNetDB.StoreRouterInfo").Warn("cannot serialize RouterInfo")
		return
	}
	if err := db.StoreRouterInfoFromMessage(hash, data, 0); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":   "StdNetDB.StoreRouterInfo",
			"hash": hash.String(),
		}).Warn("failed to store RouterInfo in NetDB")
	}
}

// ensure that the network database exists and load existing RouterInfos
func (db *StdNetDB) Ensure() (err error) {
	if !db.Exists() {
		log.WithFields(logger.Fields{"at": "Ensure"}).Debug("NetDB directory does not exist, creating it")
		err = db.Create()
	} else {
		log.WithFields(logger.Fields{"at": "Ensure"}).Debug("NetDB directory already exists")
		// Load existing RouterInfos from disk into memory
		if loadErr := db.loadExistingRouterInfos(); loadErr != nil {
			log.WithError(loadErr).Warn("Failed to load some existing RouterInfos, continuing anyway")
		}
		// Load existing LeaseSets from disk into memory (skipping expired ones)
		if loadErr := db.loadExistingLeaseSets(); loadErr != nil {
			log.WithError(loadErr).Warn("Failed to load some existing LeaseSets, continuing anyway")
		}
	}
	return err
}

// loadExistingRouterInfos scans the NetDB directory and loads all RouterInfo files into memory.
func (db *StdNetDB) loadExistingRouterInfos() error {
	basePath := db.Path()
	loaded := 0
	errors := 0

	log.WithField("path", basePath).Info("Loading existing RouterInfos from NetDB")

	// First, check the root directory (some implementations store files there)
	loaded, errors = db.scanDirectoryForRouterInfos(basePath, loaded, errors)

	// Walk through all r* subdirectories in the skiplist
	for _, c := range base64.I2PEncodeAlphabet {
		dirPath := filepath.Join(basePath, fmt.Sprintf("r%c", c))
		loaded, errors = db.scanDirectoryForRouterInfos(dirPath, loaded, errors)
	}

	log.WithFields(logger.Fields{
		"loaded": loaded,
		"errors": errors,
		"total":  loaded + errors,
	}).Info("Completed loading RouterInfos from NetDB")

	return nil
}

// scanDirectoryForRouterInfos scans a single directory for RouterInfo files and loads them into memory
// scanDirectoryForRouterInfos scans a directory for RouterInfo files and loads them into memory.
// Returns the updated count of successfully loaded files and error count.
func (db *StdNetDB) scanDirectoryForRouterInfos(dirPath string, loaded, errors int) (int, int) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		// Skip if directory doesn't exist or can't be read
		return loaded, errors
	}

	for _, entry := range entries {
		loadedOne, hadError := db.processRouterInfoEntry(dirPath, entry)
		if loadedOne {
			loaded++
		}
		if hadError {
			errors++
		}
	}

	return loaded, errors
}

// processRouterInfoEntry processes a single directory entry and attempts to load it as a RouterInfo.
// Returns whether a RouterInfo was successfully loaded and whether an error occurred.
func (db *StdNetDB) processRouterInfoEntry(dirPath string, entry os.DirEntry) (loaded, hadError bool) {
	if !db.isValidRouterInfoFile(entry) {
		return false, false
	}

	hash, err := db.extractHashFromFilename(entry.Name())
	if err != nil {
		log.WithError(err).WithField("filename", entry.Name()).Debug("Failed to decode hash from filename")
		return false, true
	}

	if db.isRouterInfoAlreadyLoaded(hash) {
		return false, false
	}

	filePath := filepath.Join(dirPath, entry.Name())
	ri, err := db.loadAndParseRouterInfo(filePath)
	if err != nil {
		log.WithError(err).WithField("file", filePath).Debug("Failed to load RouterInfo")
		return false, true
	}

	contentHash, err := db.computeRouterInfoHash(ri, filePath)
	if err != nil {
		log.WithError(err).WithField("file", filePath).Debug("Failed to compute RouterInfo hash")
		return false, true
	}

	db.storeRouterInfo(contentHash, ri)
	return true, false
}

// isValidRouterInfoFile checks if a directory entry is a valid RouterInfo file.
func (db *StdNetDB) isValidRouterInfoFile(entry os.DirEntry) bool {
	if entry.IsDir() {
		return false
	}
	if !strings.HasSuffix(entry.Name(), ".dat") {
		return false
	}
	return strings.HasPrefix(entry.Name(), "routerInfo-")
}

// extractHashFromPrefixedFilename extracts and decodes the hash from a filename
// with the given prefix and ".dat" suffix. Format: <prefix><base64hash>.dat
func extractHashFromPrefixedFilename(filename, prefix string) (common.Hash, error) {
	var hash common.Hash

	hashStr := strings.TrimPrefix(filename, prefix)
	hashStr = strings.TrimSuffix(hashStr, ".dat")

	hashBytes, err := base64.I2PEncoding.DecodeString(hashStr)
	if err != nil {
		return hash, err
	}

	copy(hash[:], hashBytes)
	return hash, nil
}

// extractHashFromFilename extracts and decodes the hash from a RouterInfo filename.
// Expected format: routerInfo-<base64hash>.dat
func (db *StdNetDB) extractHashFromFilename(filename string) (common.Hash, error) {
	return extractHashFromPrefixedFilename(filename, "routerInfo-")
}

// isRouterInfoAlreadyLoaded checks if a RouterInfo with the given hash is already in memory.
func (db *StdNetDB) isRouterInfoAlreadyLoaded(hash common.Hash) bool {
	db.riMutex.RLock()
	_, exists := db.RouterInfos[hash]
	db.riMutex.RUnlock()
	return exists
}

// loadAndParseRouterInfo loads and parses a RouterInfo from a skiplist file,
// properly stripping entry framing (1-byte type code + 2-byte length prefix).
// The loaded RouterInfo is signature-verified to prevent loading tampered data.
func (db *StdNetDB) loadAndParseRouterInfo(filePath string) (*router_info.RouterInfo, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entry := &Entry{}
	if err := entry.Deserialize(f); err != nil {
		return nil, oops.Errorf("failed to read RouterInfo entry: %w", err)
	}

	if entry.RouterInfo == nil {
		return nil, oops.Errorf("file does not contain a RouterInfo entry")
	}

	// Verify cryptographic signature to prevent loading tampered RouterInfos.
	// Network-received and reseeded RouterInfos are already verified; disk-loaded
	// ones must be verified too in case the netdb directory was tampered with.
	if err := verifyRouterInfoSignature(*entry.RouterInfo); err != nil {
		return nil, oops.Errorf("RouterInfo signature verification failed: %w", err)
	}

	return entry.RouterInfo, nil
}

// computeRouterInfoHash computes the identity hash from a RouterInfo's content.
func (db *StdNetDB) computeRouterInfoHash(ri *router_info.RouterInfo, filePath string) (common.Hash, error) {
	var contentHash common.Hash

	identHash, err := ri.IdentHash()
	if err != nil {
		return contentHash, err
	}

	identHashBytes := identHash.Bytes()
	copy(contentHash[:], identHashBytes[:])

	return contentHash, nil
}

// storeRouterInfo adds a RouterInfo to the in-memory cache.
func (db *StdNetDB) storeRouterInfo(hash common.Hash, ri *router_info.RouterInfo) {
	db.riMutex.Lock()
	db.RouterInfos[hash] = Entry{
		RouterInfo: ri,
	}
	db.riMutex.Unlock()
}

// leaseSetLoadCounts tracks the running totals during LeaseSet loading.
type leaseSetLoadCounts struct {
	loaded  int
	expired int
	errors  int
}

// loadExistingLeaseSets scans the NetDB directory and loads all unexpired LeaseSet files into memory.
// Expired LeaseSets are removed from disk during the scan.
func (db *StdNetDB) loadExistingLeaseSets() error {
	basePath := db.Path()
	counts := &leaseSetLoadCounts{}

	log.WithField("path", basePath).Info("Loading existing LeaseSets from NetDB")

	for _, c := range base64.I2PEncodeAlphabet {
		dirPath := filepath.Join(basePath, fmt.Sprintf("l%c", c))
		db.loadLeaseSetDirectory(dirPath, counts)
	}

	log.WithFields(logger.Fields{
		"loaded":  counts.loaded,
		"expired": counts.expired,
		"errors":  counts.errors,
		"total":   counts.loaded + counts.expired + counts.errors,
	}).Info("Completed loading LeaseSets from NetDB")

	return nil
}

// loadLeaseSetDirectory scans a single skiplist subdirectory for LeaseSet files
// and loads valid, unexpired entries into memory.
func (db *StdNetDB) loadLeaseSetDirectory(dirPath string, counts *leaseSetLoadCounts) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return
	}

	for _, dirEntry := range entries {
		if !db.isLeaseSetFile(dirEntry) {
			continue
		}
		db.processLeaseSetFile(dirPath, dirEntry, counts)
	}
}

// isLeaseSetFile checks whether a directory entry is a LeaseSet data file.
func (db *StdNetDB) isLeaseSetFile(entry os.DirEntry) bool {
	return !entry.IsDir() &&
		strings.HasSuffix(entry.Name(), ".dat") &&
		strings.HasPrefix(entry.Name(), "leaseSet-")
}

// processLeaseSetFile attempts to load a single LeaseSet file, removing it if expired
// and caching it if valid.
func (db *StdNetDB) processLeaseSetFile(dirPath string, dirEntry os.DirEntry, counts *leaseSetLoadCounts) {
	filePath := filepath.Join(dirPath, dirEntry.Name())
	hash, err := db.extractHashFromLeaseSetFilename(dirEntry.Name())
	if err != nil {
		log.WithError(err).WithField("filename", dirEntry.Name()).Debug("Failed to decode hash from LeaseSet filename")
		counts.errors++
		return
	}

	db.lsMutex.RLock()
	_, exists := db.LeaseSets[hash]
	db.lsMutex.RUnlock()
	if exists {
		return
	}

	entry, err := db.loadLeaseSetEntryFromFile(filePath)
	if err != nil {
		log.WithError(err).WithField("file", dirEntry.Name()).Debug("Failed to load LeaseSet from file")
		counts.errors++
		return
	}

	if db.isLeaseSetEntryExpired(entry) {
		log.WithField("hash", fmt.Sprintf("%x", hash[:8])).Debug("Removing expired LeaseSet file")
		os.Remove(filePath)
		counts.expired++
		return
	}

	db.cacheLeaseSetEntry(hash, entry)
	counts.loaded++
}

// extractHashFromLeaseSetFilename extracts and decodes the hash from a LeaseSet filename.
// Expected format: leaseSet-<base64hash>.dat
func (db *StdNetDB) extractHashFromLeaseSetFilename(filename string) (common.Hash, error) {
	return extractHashFromPrefixedFilename(filename, "leaseSet-")
}

// loadLeaseSetEntryFromFile reads an Entry from a LeaseSet .dat file.
func (db *StdNetDB) loadLeaseSetEntryFromFile(filePath string) (*Entry, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, oops.Errorf("failed to open LeaseSet file: %w", err)
	}
	defer f.Close()

	entry := &Entry{}
	if err := entry.Deserialize(f); err != nil {
		return nil, oops.Errorf("failed to read LeaseSet entry: %w", err)
	}

	return entry, nil
}

// isLeaseSetEntryExpired checks whether a LeaseSet entry has already expired.
func (db *StdNetDB) isLeaseSetEntryExpired(entry *Entry) bool {
	now := time.Now()

	if entry.LeaseSet != nil {
		exp, err := entry.LeaseSet.NewestExpiration()
		if err == nil && now.After(exp.Time()) {
			return true
		}
		return false
	}
	if entry.LeaseSet2 != nil {
		return now.After(entry.LeaseSet2.ExpirationTime())
	}
	if entry.EncryptedLeaseSet != nil {
		return now.After(entry.EncryptedLeaseSet.ExpirationTime())
	}
	if entry.MetaLeaseSet != nil {
		return now.After(entry.MetaLeaseSet.ExpirationTime())
	}
	// Unknown type — treat as expired
	return true
}

// cacheLeaseSetEntry adds a loaded LeaseSet entry to the in-memory cache and tracks its expiration.
func (db *StdNetDB) cacheLeaseSetEntry(hash common.Hash, entry *Entry) {
	db.lsMutex.Lock()
	db.LeaseSets[hash] = *entry
	db.lsMutex.Unlock()

	// Track expiration for cleanup
	if entry.LeaseSet != nil {
		db.trackLeaseSetExpiration(hash, *entry.LeaseSet)
	} else if entry.LeaseSet2 != nil {
		db.trackLeaseSet2Expiration(hash, *entry.LeaseSet2)
	} else if entry.EncryptedLeaseSet != nil {
		db.trackEncryptedLeaseSetExpiration(hash, *entry.EncryptedLeaseSet)
	} else if entry.MetaLeaseSet != nil {
		db.trackMetaLeaseSetExpiration(hash, *entry.MetaLeaseSet)
	}
}

// create base network database directory
// createRootDirectory creates the root network database directory.
// Returns the directory mode and any error encountered.
func (db *StdNetDB) createRootDirectory() (os.FileMode, error) {
	mode := os.FileMode(0o700)
	p := db.Path()
	log.WithField("path", p).Debug("Creating network database directory")
	err := os.MkdirAll(p, mode)
	if err != nil {
		log.WithError(err).Error("Failed to create root network database directory")
	}
	return mode, err
}

// createSkiplistSubdirectories creates all subdirectories for a skiplist with the given prefix.
// The prefix should be "r" for RouterInfo or "l" for LeaseSet.
func (db *StdNetDB) createSkiplistSubdirectories(prefix string, mode os.FileMode) error {
	p := db.Path()
	for _, c := range base64.I2PEncodeAlphabet {
		err := os.MkdirAll(filepath.Join(p, fmt.Sprintf("%s%c", prefix, c)), mode)
		if err != nil {
			log.WithError(err).WithField("prefix", prefix).Error("Failed to create skiplist subdirectory")
			return err
		}
	}
	return nil
}

// Create initializes the on-disk NetDB directory structure, creating the root directory
// and all skiplist subdirectories for RouterInfo and LeaseSet storage.
func (db *StdNetDB) Create() (err error) {
	mode, err := db.createRootDirectory()
	if err != nil {
		return err
	}

	// create all subdirectories for RouterInfo skiplist (r prefix)
	if err = db.createSkiplistSubdirectories("r", mode); err != nil {
		return err
	}

	// create all subdirectories for LeaseSet skiplist (l prefix)
	if err = db.createSkiplistSubdirectories("l", mode); err != nil {
		return err
	}

	return nil
}

// GetRouterInfoBytes retrieves RouterInfo data as bytes from the database
func (db *StdNetDB) GetRouterInfoBytes(hash common.Hash) ([]byte, error) {
	log.WithField("hash", hash).Debug("Getting RouterInfo bytes")

	// Check memory cache first
	db.riMutex.RLock()
	if ri, ok := db.RouterInfos[hash]; ok && ri.RouterInfo != nil {
		db.riMutex.RUnlock()
		log.WithFields(logger.Fields{"at": "GetRouterInfoBytes"}).Debug("RouterInfo found in memory cache")

		// Serialize the RouterInfo to bytes
		data, err := ri.RouterInfo.Bytes()
		if err != nil {
			log.WithError(err).Error("Failed to serialize cached RouterInfo")
			return nil, oops.Errorf("failed to serialize RouterInfo: %w", err)
		}
		return data, nil
	}
	db.riMutex.RUnlock()

	// Load from file if not in memory
	data, err := db.loadRouterInfoFromFile(hash)
	if err != nil {
		log.WithError(err).Debug("RouterInfo not found in filesystem")
		return nil, oops.Errorf("RouterInfo not found: %w", err)
	}

	// Parse and cache for future use
	_, err = db.parseAndCacheRouterInfo(hash, data)
	if err != nil {
		log.WithError(err).Error("Failed to parse RouterInfo from file")
		return nil, oops.Errorf("failed to parse RouterInfo: %w", err)
	}

	return data, nil
}

// GetRouterInfoCount returns the total number of RouterInfo entries in the database
func (db *StdNetDB) GetRouterInfoCount() int {
	return db.Size()
}

// IsFloodfill returns whether this router is configured to operate as a floodfill router.
// This checks the global router configuration for the floodfill flag.
func (db *StdNetDB) IsFloodfill() bool {
	cfg := config.GetRouterConfig()
	return cfg.NetDb.FloodfillEnabled
}

// GetActivePeerCount returns the number of peers with successful connections in the last hour.
// Active peers are those we have successfully communicated with recently, indicating they are
// currently online and reachable. This is useful for monitoring network connectivity and
// determining the health of our peer connections.
func (db *StdNetDB) GetActivePeerCount() int {
	if db.PeerTracker == nil {
		return 0
	}

	hourAgo := time.Now().Add(-1 * time.Hour)
	count := 0

	// Iterate through all tracked peers and count those with recent successful connections
	db.riMutex.RLock()
	defer db.riMutex.RUnlock()

	for hash := range db.RouterInfos {
		stats := db.PeerTracker.GetStats(hash)
		if stats != nil && !stats.LastSuccess.IsZero() && stats.LastSuccess.After(hourAgo) {
			count++
		}
	}

	log.WithFields(logger.Fields{
		"active_peers": count,
		"threshold":    "1 hour",
	}).Debug("Counted active peers")

	return count
}

// GetFastPeerCount returns the number of peers with low latency (fast response times).
// Fast peers are those with average response times under 500ms, making them good
// candidates for tunnel building and high-performance operations.
//
// Classification criteria:
//   - Average response time < 500ms
//   - Minimum 3 successful connections for statistical significance
func (db *StdNetDB) GetFastPeerCount() int {
	if db.PeerTracker == nil {
		return 0
	}

	const fastThresholdMs = 500
	const minAttempts = 3
	count := 0

	db.riMutex.RLock()
	defer db.riMutex.RUnlock()

	for hash := range db.RouterInfos {
		stats := db.PeerTracker.GetStats(hash)
		if stats != nil &&
			stats.TotalAttempts >= minAttempts &&
			stats.AvgResponseTimeMs > 0 &&
			stats.AvgResponseTimeMs < fastThresholdMs {
			count++
		}
	}

	log.WithFields(logger.Fields{
		"fast_peers":   count,
		"threshold_ms": fastThresholdMs,
		"min_attempts": minAttempts,
	}).Debug("Counted fast peers")

	return count
}

// GetHighCapacityPeerCount returns the number of high-capacity peers.
// High-capacity peers are reliable routers with good performance and high availability,
// making them excellent candidates for important roles like tunnel building.
//
// Classification criteria:
//   - Success rate >= 80%
//   - Minimum 5 connection attempts for statistical significance
//   - Average response time < 1000ms (1 second)
//   - Not marked as stale
func (db *StdNetDB) GetHighCapacityPeerCount() int {
	if db.PeerTracker == nil {
		return 0
	}

	const minSuccessRate = 0.80
	const maxResponseMs = 1000
	const minAttempts = 5
	count := 0

	db.riMutex.RLock()
	defer db.riMutex.RUnlock()

	for hash := range db.RouterInfos {
		stats := db.PeerTracker.GetStats(hash)
		if stats == nil || stats.TotalAttempts < minAttempts {
			continue
		}

		successRate := float64(stats.SuccessCount) / float64(stats.TotalAttempts)
		isStale := db.PeerTracker.IsLikelyStale(hash)

		if successRate >= minSuccessRate &&
			stats.AvgResponseTimeMs > 0 &&
			stats.AvgResponseTimeMs < maxResponseMs &&
			!isStale {
			count++
		}
	}

	log.WithFields(logger.Fields{
		"high_capacity_peers": count,
		"min_success_rate":    minSuccessRate,
		"max_response_ms":     maxResponseMs,
		"min_attempts":        minAttempts,
	}).Debug("Counted high-capacity peers")

	return count
}

// riRefreshCooldownDuration is the minimum time between RouterInfo cache
// evictions for the same peer (prevents thundering-herd re-fetches).
const riRefreshCooldownDuration = 5 * time.Minute

// RequestRouterInfoRefresh evicts a peer's RouterInfo from the in-memory cache
// so that subsequent peer selection will not reuse the stale entry. The method
// enforces a per-peer cooldown of riRefreshCooldownDuration to prevent
// repeated evictions (e.g. when a key-rotated peer causes many handshake
// failures in quick succession).
//
// After eviction the entry will be re-populated on the next reseed or
// bootstrap cycle.
func (db *StdNetDB) RequestRouterInfoRefresh(hash common.Hash) {
	now := time.Now()
	// Enforce cool-down: if a refresh was already requested recently, skip.
	if prev, loaded := db.riRefreshCooldown.Load(hash); loaded {
		if prevTime, ok := prev.(time.Time); ok && now.Sub(prevTime) < riRefreshCooldownDuration {
			log.WithFields(logger.Fields{
				"peer_hash": fmt.Sprintf("%x", hash[:8]),
				"next_in":   riRefreshCooldownDuration - now.Sub(prevTime),
			}).Debug("RouterInfo refresh skipped: cooldown in effect")
			return
		}
	}
	db.riRefreshCooldown.Store(hash, now)

	db.riMutex.Lock()
	_, existed := db.RouterInfos[hash]
	delete(db.RouterInfos, hash)
	db.riMutex.Unlock()

	if existed {
		log.WithFields(logger.Fields{
			"at":        "StdNetDB.RequestRouterInfoRefresh",
			"peer_hash": fmt.Sprintf("%x", hash[:8]),
			"reason":    "stale RouterInfo evicted after handshake EOF",
		}).Info("Evicted stale RouterInfo from cache; will be refreshed on next reseed")
	}
}

// sweepRefreshCooldown removes entries from riRefreshCooldown that are older
// than riRefreshCooldownDuration. This prevents unbounded growth of the
// sync.Map over the lifetime of a long-running router.
func (db *StdNetDB) sweepRefreshCooldown() {
	now := time.Now()
	swept := 0
	db.riRefreshCooldown.Range(func(key, value any) bool {
		if t, ok := value.(time.Time); ok && now.Sub(t) > riRefreshCooldownDuration {
			db.riRefreshCooldown.Delete(key)
			swept++
		}
		return true
	})
	if swept > 0 {
		log.WithFields(logger.Fields{
			"at":    "StdNetDB.sweepRefreshCooldown",
			"swept": swept,
		}).Debug("Swept expired riRefreshCooldown entries")
	}
}
