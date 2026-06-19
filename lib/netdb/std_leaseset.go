package netdb

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/base64"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/common/meta_leaseset"
)

// ======================================================================
// LeaseSet Storage and Retrieval Methods
// ======================================================================

// SkiplistFileForLeaseSet generates the skiplist file path for a LeaseSet
// LeaseSets use 'l' prefix instead of 'r' for router infos
func (db *StdNetDB) SkiplistFileForLeaseSet(hash common.Hash) string {
	fname := base64.EncodeToString(hash[:])
	fpath := filepath.Join(db.Path(), fmt.Sprintf("l%c", fname[0]), fmt.Sprintf("leaseSet-%s.dat", fname))
	log.WithField("file_path", fpath).Debug("Generated LeaseSet skiplist file path")
	return fpath
}

// StoreLeaseSet stores a LeaseSet entry in the database from I2NP DatabaseStore message.
// This method validates and dispatches to the appropriate typed store method based on dataType.
// Accepts dataType 1 (LeaseSet), 3 (LeaseSet2), 5 (EncryptedLeaseSet), and 7 (MetaLeaseSet).
func (db *StdNetDB) StoreLeaseSet(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("Storing LeaseSet from DatabaseStore message")

	if err := validateLeaseSetDataType(dataType); err != nil {
		return err
	}

	return db.dispatchLeaseSetStore(key, data, dataType)
}

// dispatchLeaseSetStore routes to the typed store method for non-standard
// LeaseSet variants, or handles standard LeaseSet (type 1) inline.
func (db *StdNetDB) dispatchLeaseSetStore(key common.Hash, data []byte, dataType byte) error {
	switch dataType {
	case leaseSet2Type:
		return db.StoreLeaseSet2(key, data, dataType)
	case encryptedLeaseSetType:
		return db.StoreEncryptedLeaseSet(key, data, dataType)
	case metaLeaseSetType:
		return db.StoreMetaLeaseSet(key, data, dataType)
	default:
		return db.storeStandardLeaseSet(key, data)
	}
}

// storeStandardLeaseSet parses, verifies, caches, and persists a standard
// type-1 LeaseSet.
func (db *StdNetDB) storeStandardLeaseSet(key common.Hash, data []byte) error {
	ls, err := parseLeaseSetData(data)
	if err != nil {
		return err
	}

	if err := verifyLeaseSetHash(key, ls); err != nil {
		return err
	}

	// Verify cryptographic signature before accepting into cache
	if err := ls.Verify(); err != nil {
		log.WithError(err).WithField("hash", key).Warn("LeaseSet signature verification failed")
		return oops.Errorf("LeaseSet signature verification failed: %w", err)
	}

	if !db.addLeaseSetToCache(key, ls) {
		return nil
	}

	if err := db.persistLeaseSetToFilesystem(key, ls); err != nil {
		return err
	}

	log.WithField("hash", key).Debug("Successfully stored LeaseSet")
	return nil
}

// Valid LeaseSet data type constants matching I2NP DatabaseStore specification.
// These mirror the constants in lib/i2np/database_store.go to avoid a circular import.
const (
	leaseSetType          byte = 1 // Standard LeaseSet
	leaseSet2Type         byte = 3 // LeaseSet2 (standard since 0.9.38)
	encryptedLeaseSetType byte = 5 // EncryptedLeaseSet (0.9.39+)
	metaLeaseSetType      byte = 7 // MetaLeaseSet (0.9.40+)
)

// validateLeaseSetDataType checks if the data type is valid for any LeaseSet variant.
// Accepts types 1 (LeaseSet), 3 (LeaseSet2), 5 (EncryptedLeaseSet), and 7 (MetaLeaseSet).
func validateLeaseSetDataType(dataType byte) error {
	switch dataType {
	case leaseSetType, leaseSet2Type, encryptedLeaseSetType, metaLeaseSetType:
		return nil
	default:
		log.WithField("type", dataType).Warn("Invalid data type for LeaseSet")
		return oops.Errorf("invalid data type for LeaseSet: expected 1, 3, 5, or 7, got %d", dataType)
	}
}

// parseLeaseSetData parses LeaseSet from raw bytes using the common library.
func parseLeaseSetData(data []byte) (lease_set.LeaseSet, error) {
	ls, err := lease_set.ReadLeaseSet(data)
	if err != nil {
		log.WithError(err).Error("Failed to parse LeaseSet from DatabaseStore data")
		return lease_set.LeaseSet{}, oops.Errorf("failed to parse LeaseSet: %w", err)
	}
	return ls, nil
}

// verifyHashMatch computes the hash of destBytes and returns an error if it does
// not match the expected key. typeName is included in log and error messages.
func verifyHashMatch(key common.Hash, destBytes []byte, typeName string) error {
	expectedHash := common.HashData(destBytes)
	if key != expectedHash {
		log.WithFields(logger.Fields{
			"expected_hash": expectedHash,
			"provided_key":  key,
		}).Error(typeName + " hash mismatch")
		return oops.Errorf("%s hash mismatch: expected %x, got %x", typeName, expectedHash, key)
	}
	return nil
}

// verifyDestinationHashBytes is a generic helper that consolidates the pattern of
// getting bytes from a Bytes() provider and verifying the hash.
func verifyDestinationHashBytes[T interface{ Bytes() ([]byte, error) }](key common.Hash, dest T, typeName string) error {
	destBytes, err := dest.Bytes()
	if err != nil {
		return oops.Errorf("failed to get destination bytes: %w", err)
	}
	return verifyHashMatch(key, destBytes, typeName)
}

// verifyLeaseSetHash validates that the provided key matches the LeaseSet destination hash.
func verifyLeaseSetHash(key common.Hash, ls lease_set.LeaseSet) error {
	return verifyDestinationHashBytes(key, ls.Destination(), "LeaseSet")
}

// addLeaseSetToCache adds a LeaseSet entry to the in-memory cache.
// If an entry already exists, it is replaced only if the new LeaseSet
// has newer lease expirations. Returns true if the entry was added or updated.
// Also tracks the expiration time for automatic cleanup.
// Enforces capacity limits and per-source admission control to prevent
// unbounded memory growth and remote memory-DoS attacks.
func (db *StdNetDB) addLeaseSetToCache(key common.Hash, ls lease_set.LeaseSet) bool {
	db.lsCache.mu.Lock()
	defer db.lsCache.mu.Unlock()

	if existing, exists := db.lsCache.entries[key]; exists {
		// Existing LeaseSet: compare by newest expiration — a LeaseSet with later expirations is newer.
		if existing.LeaseSet != nil {
			existExp, err1 := existing.LeaseSet.NewestExpiration()
			newExp, err2 := ls.NewestExpiration()
			if err1 == nil && err2 == nil && !newExp.Time().After(existExp.Time()) {
				log.WithField("hash", key).Debug("LeaseSet already exists with same or newer expiration, skipping")
				return false
			}
		}
		log.WithField("hash", key).Debug("Replacing stale LeaseSet with newer version")
		// Lock is already held, use locked variant
		db.trackLeaseSetExpirationLocked(key, ls, true)
		db.lsCache.entries[key] = Entry{
			LeaseSet: &ls,
		}
		return true
	}

	// New LeaseSet: check admission limits and capacity without releasing the lock.
	// Releasing and re-acquiring the lock here would allow concurrent writers to
	// invalidate the count and capacity snapshot (TOCTOU), potentially bypassing
	// capacity limits.
	currentCount := len(db.lsCache.entries)

	err := db.checkLeaseSetAdmissionLimits(key, nil, currentCount)
	if err != nil {
		log.WithField("hash", key).Debug("LeaseSet introduction rejected by admission control")
		return false
	}

	// Check capacity and evict if needed. evictSoonestExpiringLeaseSet acquires
	// db.lsCache.mu internally, so release our lock first, evict, then re-acquire
	// and re-read the count to confirm we still have room.
	maxCapacity := db.lsCache.capacity
	if maxCapacity > 0 && len(db.lsCache.entries) >= maxCapacity {
		db.lsCache.mu.Unlock()
		db.evictSoonestExpiringLeaseSet()
		db.lsCache.mu.Lock()
		// After eviction, verify we have room; another writer may have filled it.
		if len(db.lsCache.entries) >= maxCapacity {
			log.WithField("hash", key).Debug("LeaseSet dropped: cache still at capacity after eviction")
			return false
		}
	}

	// Track expiration time for cleanup FIRST (lock is held)
	// This ensures the entry has an expiry time before it's visible in the cache
	db.trackLeaseSetExpirationLocked(key, ls, true)

	db.lsCache.entries[key] = Entry{
		LeaseSet: &ls,
	}

	return true
}

// persistLeaseSetEntryToFile writes an Entry to the lease set skiplist file for the given key.
// typeName is used in log and error messages. Filesystem persistence is best-effort;
// a transient I/O error does not remove valid cached data.
func (db *StdNetDB) persistLeaseSetEntryToFile(key common.Hash, entry *Entry, typeName string) (err error) {
	fpath := db.SkiplistFileForLeaseSet(key)
	f, ferr := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if ferr != nil {
		log.WithError(ferr).Warn(fmt.Sprintf("Failed to open file for saving %s (in-memory entry preserved)", typeName))
		return oops.Errorf("failed to open %s file: %w", typeName, ferr)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if serr := entry.Serialize(f); serr != nil {
		log.WithError(serr).Warn(fmt.Sprintf("Failed to write %s to filesystem (in-memory entry preserved)", typeName))
		return oops.Errorf("failed to save %s to filesystem: %w", typeName, serr)
	}

	return nil
}

// persistLeaseSetToFilesystem saves a LeaseSet entry to the filesystem.
func (db *StdNetDB) persistLeaseSetToFilesystem(key common.Hash, ls lease_set.LeaseSet) error {
	return db.persistLeaseSetEntryToFile(key, &Entry{LeaseSet: &ls}, "LeaseSet")
}

// emptyChannel returns a closed empty channel for the provided type.
func emptyChannel[T any]() chan T {
	ch := make(chan T)
	close(ch)
	return ch
}

// valueChannel returns a closed channel containing a single value for the provided type.
func valueChannel[T any](value T) chan T {
	ch := make(chan T, 1)
	ch <- value
	close(ch)
	return ch
}

type leaseSetVariantGetter[T any] struct {
	typeName    string
	cacheLookup func(common.Hash) (T, bool)
	load        func(common.Hash) (T, error)
}

func getLeaseSetVariant[T any](hash common.Hash, getter leaseSetVariantGetter[T]) chan T {
	log.WithField("hash", hash).Debug("Getting " + getter.typeName)

	if value, ok := getter.cacheLookup(hash); ok {
		return valueChannel(value)
	}

	value, err := getter.load(hash)
	if err != nil {
		return emptyChannel[T]()
	}

	return valueChannel(value)
}

// emptyLeaseSetChannel returns a closed empty channel indicating LeaseSet not found.
func emptyLeaseSetChannel() chan lease_set.LeaseSet {
	return emptyChannel[lease_set.LeaseSet]()
}

// leaseSetChannel returns a channel containing the given LeaseSet.
func leaseSetChannel(ls lease_set.LeaseSet) chan lease_set.LeaseSet {
	return valueChannel(ls)
}

// emptyLeaseSet2Channel returns a closed empty channel indicating LeaseSet2 not found.
func emptyLeaseSet2Channel() chan lease_set2.LeaseSet2 {
	return emptyChannel[lease_set2.LeaseSet2]()
}

// leaseSet2Channel returns a channel containing the given LeaseSet2.
func leaseSet2Channel(ls2 lease_set2.LeaseSet2) chan lease_set2.LeaseSet2 {
	return valueChannel(ls2)
}

// emptyEncryptedLeaseSetChannel returns a closed empty channel indicating EncryptedLeaseSet not found.
func emptyEncryptedLeaseSetChannel() chan encrypted_leaseset.EncryptedLeaseSet {
	return emptyChannel[encrypted_leaseset.EncryptedLeaseSet]()
}

// encryptedLeaseSetChannel returns a channel containing the given EncryptedLeaseSet.
func encryptedLeaseSetChannel(els encrypted_leaseset.EncryptedLeaseSet) chan encrypted_leaseset.EncryptedLeaseSet {
	return valueChannel(els)
}

// emptyMetaLeaseSetChannel returns a closed empty channel indicating MetaLeaseSet not found.
func emptyMetaLeaseSetChannel() chan meta_leaseset.MetaLeaseSet {
	return emptyChannel[meta_leaseset.MetaLeaseSet]()
}

// metaLeaseSetChannel returns a channel containing the given MetaLeaseSet.
func metaLeaseSetChannel(mls meta_leaseset.MetaLeaseSet) chan meta_leaseset.MetaLeaseSet {
	return valueChannel(mls)
}

// GetLeaseSet retrieves a LeaseSet from the database by its hash.
// Returns a channel that yields the LeaseSet or nil if not found.
// Checks memory cache first, then loads from filesystem if necessary.
func (db *StdNetDB) GetLeaseSet(hash common.Hash) (chnl chan lease_set.LeaseSet) {
	log.WithField("hash", hash).Debug("Getting LeaseSet")

	if chnl = db.getLeaseSetFromCache(hash); chnl != nil {
		return chnl
	}

	return db.loadLeaseSetFromDisk(hash)
}

// getLeaseSetFromCache attempts to retrieve a LeaseSet from the memory cache.
// Returns nil if not in cache, indicating caller should try disk.
func (db *StdNetDB) getLeaseSetFromCache(hash common.Hash) chan lease_set.LeaseSet {
	entry, ok := db.lsCache.get(hash)

	if !ok {
		return nil // Not in cache, try disk
	}

	if entry.LeaseSet == nil {
		log.WithField("hash", hash).Debug("Entry found but is not a classic LeaseSet")
		return emptyLeaseSetChannel()
	}

	if db.isLeaseSetExpired(hash) {
		log.WithField("hash", hash).Debug("LeaseSet expired, not serving from cache")
		return emptyLeaseSetChannel()
	}

	log.WithFields(logger.Fields{"at": "getLeaseSetFromCache"}).Debug("LeaseSet found in memory cache")
	return leaseSetChannel(*entry.LeaseSet)
}

// loadLeaseSetFromDisk loads a LeaseSet from filesystem and caches it.
func (db *StdNetDB) loadLeaseSetFromDisk(hash common.Hash) chan lease_set.LeaseSet {
	entry, err := db.loadLeaseSetEntryFromFile(db.SkiplistFileForLeaseSet(hash))
	if err != nil {
		log.WithError(err).Debug("Failed to load LeaseSet entry from file")
		return emptyLeaseSetChannel()
	}

	if entry.LeaseSet == nil {
		log.WithField("hash", hash).Debug("On-disk entry is not a classic LeaseSet")
		return emptyLeaseSetChannel()
	}

	db.lsCache.put(hash, Entry{LeaseSet: entry.LeaseSet})

	return leaseSetChannel(*entry.LeaseSet)
}

// loadLeaseSetFromFile loads a LeaseSet entry from the skiplist file,
// stripping the entry framing (1-byte type code + 2-byte length prefix)
// that was written by Entry.WriteTo. Returns the unframed payload data.
func (db *StdNetDB) loadLeaseSetFromFile(hash common.Hash) ([]byte, error) {
	fname := db.SkiplistFileForLeaseSet(hash)

	entry, err := db.loadLeaseSetEntryFromFile(fname)
	if err != nil {
		return nil, oops.Errorf("failed to load LeaseSet entry: %w", err)
	}

	return db.serializeEntry(entry)
}

// serializeEntry serializes the first non-nil data type in an Entry
// back to raw bytes suitable for parsing by the type-specific parsers.
// entrySerializer pairs an entry type name with a function to serialize it.
type entrySerializer struct {
	name      string
	serialize func() ([]byte, error)
}

// serializeEntry converts a NetDB entry to its byte representation.
// It checks each possible entry type (LeaseSet, LeaseSet2, EncryptedLeaseSet,
// MetaLeaseSet, RouterInfo) and serializes the first one found.
func (db *StdNetDB) serializeEntry(entry *Entry) ([]byte, error) {
	serializers := db.collectSerializers(entry)
	if len(serializers) == 0 {
		return nil, oops.Errorf("entry contains no valid data")
	}
	s := serializers[0]
	data, err := s.serialize()
	if err != nil {
		return nil, oops.Errorf("failed to serialize %s from entry: %w", s.name, err)
	}
	return data, nil
}

// collectSerializers returns the serializers for all non-nil entry types.
func (db *StdNetDB) collectSerializers(entry *Entry) []entrySerializer {
	var serializers []entrySerializer
	if entry.LeaseSet != nil {
		serializers = append(serializers, entrySerializer{"LeaseSet", entry.LeaseSet.Bytes})
	}
	if entry.LeaseSet2 != nil {
		serializers = append(serializers, entrySerializer{"LeaseSet2", entry.LeaseSet2.Bytes})
	}
	if entry.EncryptedLeaseSet != nil {
		serializers = append(serializers, entrySerializer{"EncryptedLeaseSet", entry.EncryptedLeaseSet.Bytes})
	}
	if entry.MetaLeaseSet != nil {
		serializers = append(serializers, entrySerializer{"MetaLeaseSet", entry.MetaLeaseSet.Bytes})
	}
	if entry.RouterInfo != nil {
		serializers = append(serializers, entrySerializer{"RouterInfo", entry.RouterInfo.Bytes})
	}
	return serializers
}

// parseAndCacheLeaseSet parses LeaseSet data and adds it to the memory cache.
func (db *StdNetDB) parseAndCacheLeaseSet(hash common.Hash, data []byte) (lease_set.LeaseSet, error) {
	ls, err := lease_set.ReadLeaseSet(data)
	if err != nil {
		return lease_set.LeaseSet{}, oops.Errorf("failed to parse LeaseSet: %w", err)
	}

	// Always store/replace the cached entry so stale data is updated
	log.WithFields(logger.Fields{"at": "parseAndCacheLeaseSet"}).Debug("Storing LeaseSet in memory cache")
	db.lsCache.put(hash, Entry{
		LeaseSet: &ls,
	})

	return ls, nil
}

// fetchLeaseSetBytes is a generic helper for all GetXxxBytes lease set methods.
// cacheCheck extracts bytes from a cached Entry (returns nil,nil if the entry
// does not hold the desired type). parseAndCache parses raw file data and
// populates the cache, returning any error.
func (db *StdNetDB) fetchLeaseSetBytes(
	hash common.Hash,
	typeName string,
	cacheCheck func(Entry) ([]byte, error),
	parseAndCache func(common.Hash, []byte) error,
) ([]byte, error) {
	log.WithField("hash", hash).Debug("Getting " + typeName + " bytes")

	// Check memory cache first
	if data, err := db.checkCacheForLeaseSet(hash, typeName, cacheCheck); data != nil || err != nil {
		return data, err
	}

	// Load from file if not in memory
	data, err := db.loadLeaseSetFromFile(hash)
	if err != nil {
		log.WithError(err).Debug(typeName + " not found in filesystem")
		return nil, oops.Errorf("%s not found: %w", typeName, err)
	}

	// Parse and cache for future use
	if err := parseAndCache(hash, data); err != nil {
		log.WithError(err).Error("Failed to parse " + typeName + " from file")
		return nil, oops.Errorf("failed to parse %s: %w", typeName, err)
	}

	return data, nil
}

// checkCacheForLeaseSet checks the memory cache for a LeaseSet entry.
func (db *StdNetDB) checkCacheForLeaseSet(
	hash common.Hash,
	typeName string,
	cacheCheck func(Entry) ([]byte, error),
) ([]byte, error) {
	db.lsCache.mu.RLock()
	defer db.lsCache.mu.RUnlock()

	entry, ok := db.lsCache.entries[hash]
	if !ok {
		return nil, nil
	}

	data, err := cacheCheck(entry)
	if data == nil && err == nil {
		return nil, nil
	}

	if err != nil {
		log.WithError(err).Error("Failed to serialize cached " + typeName)
		return nil, oops.Errorf("failed to serialize %s: %w", typeName, err)
	}

	log.WithFields(logger.Fields{"at": "GetLeaseSet", "type": typeName}).Debug("found in memory cache")
	return data, nil
}

// GetLeaseSetBytes retrieves LeaseSet data as bytes from the database.
func (db *StdNetDB) GetLeaseSetBytes(hash common.Hash) ([]byte, error) {
	return db.fetchLeaseSetBytes(
		hash, "LeaseSet",
		func(e Entry) ([]byte, error) {
			if e.LeaseSet == nil {
				return nil, nil
			}
			return e.LeaseSet.Bytes()
		},
		func(h common.Hash, d []byte) error {
			_, err := db.parseAndCacheLeaseSet(h, d)
			return err
		},
	)
}

// GetLeaseSetCount returns the total number of LeaseSet entries in memory cache.
func (db *StdNetDB) GetLeaseSetCount() int {
	return db.lsCache.count()
}

// verifiableLeaseSet is satisfied by any lease set variant that supports
// cryptographic signature verification.
type verifiableLeaseSet interface {
	Verify() error
}

// storeLeaseSetVariant executes the common storage pipeline for all lease set
// variants: validate data type → parse → verify hash → verify signature →
// cache → persist → log success.
func (db *StdNetDB) storeLeaseSetVariant(
	key common.Hash, dataType, expectedType byte, typeName string,
	parseAndVerifyHash func() (verifiableLeaseSet, error),
	addToCache func() bool,
	persistToFS func() error,
) error {
	log.WithField("hash", key).Debugf("Storing %s from DatabaseStore message", typeName)

	if err := validateLeaseSetVariantDataType(dataType, expectedType, typeName); err != nil {
		return err
	}

	ls, err := parseAndVerifyHash()
	if err != nil {
		return err
	}

	if err := ls.Verify(); err != nil {
		log.WithError(err).WithField("hash", key).Warnf("%s signature verification failed", typeName)
		return oops.Errorf("%s signature verification failed: %w", typeName, err)
	}

	if !addToCache() {
		return nil
	}

	if err := persistToFS(); err != nil {
		return err
	}

	log.WithField("hash", key).Debugf("Successfully stored %s", typeName)
	return nil
}

// ======================================================================
// LeaseSet2 Storage and Retrieval Methods
// ======================================================================

// StoreLeaseSet2 stores a LeaseSet2 entry in the database from I2NP DatabaseStore message.
// This method validates, parses, caches, and persists LeaseSet2 data.
// dataType should be 3 for LeaseSet2 (matching I2P protocol specification).
func (db *StdNetDB) StoreLeaseSet2(key common.Hash, data []byte, dataType byte) error {
	var ls2 lease_set2.LeaseSet2
	return db.storeLeaseSetVariant(
		key, dataType, leaseSet2Type, "LeaseSet2",
		func() (verifiableLeaseSet, error) {
			var err error
			ls2, err = parseLeaseSet2Data(data)
			if err != nil {
				return nil, err
			}
			if err := verifyLeaseSet2Hash(key, ls2); err != nil {
				return nil, err
			}
			return &ls2, nil
		},
		func() bool { return db.addLeaseSet2ToCache(key, ls2) },
		func() error { return db.persistLeaseSet2ToFilesystem(key, ls2) },
	)
}

// validateLeaseSetVariantDataType checks if the data type matches the expected value for a lease set variant.
func validateLeaseSetVariantDataType(dataType, expected byte, typeName string) error {
	if dataType != expected {
		log.WithField("type", dataType).Warnf("Invalid data type for %s, expected %d", typeName, expected)
		return oops.Errorf("invalid data type for %s: expected %d, got %d", typeName, expected, dataType)
	}
	return nil
}

// parseLeaseSet2Data parses LeaseSet2 from raw bytes using the common library.
func parseLeaseSet2Data(data []byte) (lease_set2.LeaseSet2, error) {
	ls2, _, err := lease_set2.ReadLeaseSet2(data)
	if err != nil {
		log.WithError(err).Error("Failed to parse LeaseSet2 from DatabaseStore data")
		return lease_set2.LeaseSet2{}, oops.Errorf("failed to parse LeaseSet2: %w", err)
	}
	return ls2, nil
}

// verifyLeaseSet2Hash validates that the provided key matches the LeaseSet2 destination hash.
func verifyLeaseSet2Hash(key common.Hash, ls2 lease_set2.LeaseSet2) error {
	return verifyDestinationHashBytes(key, ls2.Destination(), "LeaseSet2")
}

// addLeaseSetEntryToCache stores an entry in the LeaseSet cache, replacing an
// existing entry only when isNewer returns true for the current occupant.
// trackExpiryLocked is called after a successful store while db.lsCache.mu is
// still held; it MUST use _setExpiryLocked rather than setExpiry to avoid a
// self-deadlock (setExpiry would attempt to re-acquire the same write lock).
// Returns true if stored.
func (db *StdNetDB) addLeaseSetEntryToCache(key common.Hash, entry Entry, isNewer func(Entry) bool, trackExpiryLocked func(), typeName string) bool {
	db.lsCache.mu.Lock()
	defer db.lsCache.mu.Unlock()

	if existing, exists := db.lsCache.entries[key]; exists {
		if !isNewer(existing) {
			log.WithField("hash", key).Debug(typeName + " already exists with same or newer timestamp, skipping")
			return false
		}
		log.WithField("hash", key).Debug("Replacing stale " + typeName + " with newer version")
	}

	db.lsCache.entries[key] = entry
	trackExpiryLocked()

	return true
}

// addLeaseSet2ToCache adds a LeaseSet2 entry to the in-memory cache.
// If an entry already exists, it is replaced only if the new LeaseSet2
// has a more recent Published timestamp. Returns true if the entry was
// added or updated.
func (db *StdNetDB) addLeaseSet2ToCache(key common.Hash, ls2 lease_set2.LeaseSet2) bool {
	expiryTime := ls2.ExpirationTime()
	return db.addLeaseSetEntryToCache(key, Entry{LeaseSet2: &ls2}, func(existing Entry) bool {
		if existing.LeaseSet2 == nil {
			return true
		}
		return ls2.PublishedTime().After(existing.LeaseSet2.PublishedTime())
	}, func() { db.lsCache._setExpiryLocked(key, expiryTime) }, "LeaseSet2")
}

// persistLeaseSet2ToFilesystem saves a LeaseSet2 entry to the filesystem.
func (db *StdNetDB) persistLeaseSet2ToFilesystem(key common.Hash, ls2 lease_set2.LeaseSet2) error {
	return db.persistLeaseSetEntryToFile(key, &Entry{LeaseSet2: &ls2}, "LeaseSet2")
}

// GetLeaseSet2 retrieves a LeaseSet2 from the database by its hash.
// Returns a channel that yields the LeaseSet2 or nil if not found.
// Checks memory cache first, then loads from filesystem if necessary.
func (db *StdNetDB) GetLeaseSet2(hash common.Hash) (chnl chan lease_set2.LeaseSet2) {
	return getLeaseSetVariant(hash, leaseSetVariantGetter[lease_set2.LeaseSet2]{
		typeName: "LeaseSet2",
		cacheLookup: func(hash common.Hash) (lease_set2.LeaseSet2, bool) {
			db.lsCache.mu.RLock()
			defer db.lsCache.mu.RUnlock()

			entry, ok := db.lsCache.entries[hash]
			if !ok || entry.LeaseSet2 == nil {
				return lease_set2.LeaseSet2{}, false
			}

			if db.isLeaseSetExpired(hash) {
				log.WithField("hash", hash).Debug("LeaseSet2 expired, not serving from cache")
				return lease_set2.LeaseSet2{}, false
			}

			log.WithFields(logger.Fields{"at": "GetLeaseSet2"}).Debug("LeaseSet2 found in memory cache")
			return *entry.LeaseSet2, true
		},
		load: func(hash common.Hash) (lease_set2.LeaseSet2, error) {
			data, err := db.loadLeaseSetFromFile(hash)
			if err != nil {
				log.WithError(err).Error("Failed to load LeaseSet2 from file")
				return lease_set2.LeaseSet2{}, err
			}

			ls2, err := db.parseAndCacheLeaseSet2(hash, data)
			if err != nil {
				log.WithError(err).Error("Failed to parse LeaseSet2")
				return lease_set2.LeaseSet2{}, err
			}

			return ls2, nil
		},
	})
}

// cacheLeaseSetEntryIfNewer conditionally stores entry under hash when isNewer
// returns true for the current occupant. Returns true if the entry was stored.
// Caller must NOT hold lsMutex.
func (db *StdNetDB) cacheLeaseSetEntryIfNewer(hash common.Hash, entry Entry, isNewer func(Entry) bool, typeName string) bool {
	db.lsCache.mu.Lock()
	if existing, ok := db.lsCache.entries[hash]; ok {
		if !isNewer(existing) {
			db.lsCache.mu.Unlock()
			log.WithFields(logger.Fields{"at": "cacheLeaseSetEntryIfNewer"}).Debug("Skipping " + typeName + " update — cached version is same or newer")
			return false
		}
		log.WithFields(logger.Fields{"at": "cacheLeaseSetEntryIfNewer"}).Debug("Replacing stale " + typeName + " in memory cache")
	} else {
		log.WithFields(logger.Fields{"at": "cacheLeaseSetEntryIfNewer"}).Debug("Adding " + typeName + " to memory cache")
	}
	db.lsCache.entries[hash] = entry
	db.lsCache.mu.Unlock()
	return true
}

// parseAndCacheLeaseSet2 parses LeaseSet2 data and adds it to the memory cache.
// If a cached entry already exists, the new entry replaces it only if it has a
// newer published timestamp, preventing stale data from persisting.
//
// CRITICAL-2 FIX: Added cryptographic signature verification before caching.
// LeaseSet2 must be verified against its signature to prevent attacks where
// persisted files are corrupted to inject malicious data.
func (db *StdNetDB) parseAndCacheLeaseSet2(hash common.Hash, data []byte) (lease_set2.LeaseSet2, error) {
	ls2, _, err := lease_set2.ReadLeaseSet2(data)
	if err != nil {
		return lease_set2.LeaseSet2{}, oops.Errorf("failed to parse LeaseSet2: %w", err)
	}

	// CRITICAL-2 FIX: Verify signature before accepting into cache
	// This is fail-closed: any signature verification failure is rejected completely
	if err := ls2.Verify(); err != nil {
		log.WithError(err).WithField("hash", hash).Warn("LeaseSet2 signature verification failed during retrieval")
		return lease_set2.LeaseSet2{}, oops.Errorf("LeaseSet2 signature verification failed: %w", err)
	}

	db.cacheLeaseSetEntryIfNewer(hash, Entry{LeaseSet2: &ls2}, func(existing Entry) bool {
		return existing.LeaseSet2 == nil || ls2.PublishedTime().After(existing.LeaseSet2.PublishedTime())
	}, "LeaseSet2")

	return ls2, nil
}

// GetLeaseSet2Bytes retrieves LeaseSet2 data as bytes from the database.
func (db *StdNetDB) GetLeaseSet2Bytes(hash common.Hash) ([]byte, error) {
	return db.getLeaseSetBytesWithHandlers(hash, db.leaseSet2BytesHandlers())
}

type leaseSetBytesHandlers struct {
	typeName      string
	cacheCheck    func(Entry) ([]byte, error)
	parseAndCache func(common.Hash, []byte) error
}

func (db *StdNetDB) getLeaseSetBytesWithHandlers(hash common.Hash, handlers leaseSetBytesHandlers) ([]byte, error) {
	return db.fetchLeaseSetBytes(hash, handlers.typeName, handlers.cacheCheck, handlers.parseAndCache)
}

func (db *StdNetDB) leaseSet2BytesHandlers() leaseSetBytesHandlers {
	return leaseSetBytesHandlers{
		typeName: "LeaseSet2",
		cacheCheck: func(e Entry) ([]byte, error) {
			if e.LeaseSet2 == nil {
				return nil, nil
			}
			return e.LeaseSet2.Bytes()
		},
		parseAndCache: func(h common.Hash, d []byte) error {
			_, err := db.parseAndCacheLeaseSet2(h, d)
			return err
		},
	}
}

// ======================================================================
// EncryptedLeaseSet Storage and Retrieval Methods
// ======================================================================

// StoreEncryptedLeaseSet stores an EncryptedLeaseSet entry in the database from I2NP DatabaseStore message.
// This method validates, parses, caches, and persists EncryptedLeaseSet data.
// dataType should be 5 for EncryptedLeaseSet (matching I2P protocol specification).
func (db *StdNetDB) StoreEncryptedLeaseSet(key common.Hash, data []byte, dataType byte) error {
	var els encrypted_leaseset.EncryptedLeaseSet
	return db.storeLeaseSetVariant(
		key, dataType, encryptedLeaseSetType, "EncryptedLeaseSet",
		func() (verifiableLeaseSet, error) {
			var err error
			els, err = parseEncryptedLeaseSetData(data)
			if err != nil {
				return nil, err
			}
			if err := verifyEncryptedLeaseSetHash(key, els); err != nil {
				return nil, err
			}
			return &els, nil
		},
		func() bool { return db.addEncryptedLeaseSetToCache(key, els) },
		func() error { return db.persistEncryptedLeaseSetToFilesystem(key, els) },
	)
}

// parseEncryptedLeaseSetData parses EncryptedLeaseSet from raw bytes using the common library.
func parseEncryptedLeaseSetData(data []byte) (encrypted_leaseset.EncryptedLeaseSet, error) {
	els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(data)
	if err != nil {
		log.WithError(err).Error("Failed to parse EncryptedLeaseSet from DatabaseStore data")
		return encrypted_leaseset.EncryptedLeaseSet{}, oops.Errorf("failed to parse EncryptedLeaseSet: %w", err)
	}
	return els, nil
}

// verifyEncryptedLeaseSetHash validates that the provided key matches the EncryptedLeaseSet blinded destination hash.
func verifyEncryptedLeaseSetHash(key common.Hash, els encrypted_leaseset.EncryptedLeaseSet) error {
	destBytes := els.BlindedPublicKey()
	if destBytes == nil {
		return oops.Errorf("failed to get blinded public key bytes")
	}
	return verifyHashMatch(key, destBytes, "EncryptedLeaseSet")
}

// addEncryptedLeaseSetToCache adds an EncryptedLeaseSet entry to the in-memory cache.
// If an entry already exists, it is replaced only if the new EncryptedLeaseSet
// has a more recent Published timestamp. Returns true if the entry was added or updated.
func (db *StdNetDB) addEncryptedLeaseSetToCache(key common.Hash, els encrypted_leaseset.EncryptedLeaseSet) bool {
	expiryTime := els.ExpirationTime()
	return db.addLeaseSetEntryToCache(key, Entry{EncryptedLeaseSet: &els}, func(existing Entry) bool {
		if existing.EncryptedLeaseSet == nil {
			return true
		}
		return els.PublishedTime().After(existing.EncryptedLeaseSet.PublishedTime())
	}, func() { db.lsCache._setExpiryLocked(key, expiryTime) }, "EncryptedLeaseSet")
}

// persistEncryptedLeaseSetToFilesystem saves an EncryptedLeaseSet entry to the filesystem.
func (db *StdNetDB) persistEncryptedLeaseSetToFilesystem(key common.Hash, els encrypted_leaseset.EncryptedLeaseSet) error {
	return db.persistLeaseSetEntryToFile(key, &Entry{EncryptedLeaseSet: &els}, "EncryptedLeaseSet")
}

// GetEncryptedLeaseSet retrieves an EncryptedLeaseSet from the database by its hash.
// Returns a channel that yields the EncryptedLeaseSet or nil if not found.
// Checks memory cache first, then loads from filesystem if necessary.
func (db *StdNetDB) GetEncryptedLeaseSet(hash common.Hash) (chnl chan encrypted_leaseset.EncryptedLeaseSet) {
	return getLeaseSetVariant(hash, leaseSetVariantGetter[encrypted_leaseset.EncryptedLeaseSet]{
		typeName: "EncryptedLeaseSet",
		cacheLookup: func(hash common.Hash) (encrypted_leaseset.EncryptedLeaseSet, bool) {
			db.lsCache.mu.RLock()
			defer db.lsCache.mu.RUnlock()

			entry, ok := db.lsCache.entries[hash]
			if !ok || entry.EncryptedLeaseSet == nil {
				return encrypted_leaseset.EncryptedLeaseSet{}, false
			}

			if db.isLeaseSetExpired(hash) {
				log.WithField("hash", hash).Debug("EncryptedLeaseSet expired, not serving from cache")
				return encrypted_leaseset.EncryptedLeaseSet{}, false
			}

			log.WithFields(logger.Fields{"at": "GetEncryptedLeaseSet"}).Debug("EncryptedLeaseSet found in memory cache")
			return *entry.EncryptedLeaseSet, true
		},
		load: func(hash common.Hash) (encrypted_leaseset.EncryptedLeaseSet, error) {
			data, err := db.loadLeaseSetFromFile(hash)
			if err != nil {
				log.WithError(err).Error("Failed to load EncryptedLeaseSet from file")
				return encrypted_leaseset.EncryptedLeaseSet{}, err
			}

			els, err := db.parseAndCacheEncryptedLeaseSet(hash, data)
			if err != nil {
				log.WithError(err).Error("Failed to parse EncryptedLeaseSet")
				return encrypted_leaseset.EncryptedLeaseSet{}, err
			}

			return els, nil
		},
	})
}

// parseAndCacheEncryptedLeaseSet parses EncryptedLeaseSet data and adds it to the memory cache.
// If a cached entry already exists, the new entry replaces it only if it has a
// newer published timestamp, preventing stale data from persisting.
//
// CRITICAL-2 FIX: Added cryptographic signature verification before caching.
// EncryptedLeaseSet blinded public key must be verified against the provided signature.
// This prevents attacks where persisted EncryptedLeaseSet files are corrupted to inject
// malicious blinded keys that would then be loaded without verification during retrieval.
func (db *StdNetDB) parseAndCacheEncryptedLeaseSet(hash common.Hash, data []byte) (encrypted_leaseset.EncryptedLeaseSet, error) {
	els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(data)
	if err != nil {
		return encrypted_leaseset.EncryptedLeaseSet{}, oops.Errorf("failed to parse EncryptedLeaseSet: %w", err)
	}

	// CRITICAL-2 FIX: Verify signature before accepting into cache
	// This is fail-closed: any signature verification failure is rejected completely
	if err := els.Verify(); err != nil {
		log.WithError(err).WithField("hash", hash).Warn("EncryptedLeaseSet signature verification failed during retrieval")
		return encrypted_leaseset.EncryptedLeaseSet{}, oops.Errorf("EncryptedLeaseSet signature verification failed: %w", err)
	}

	db.cacheLeaseSetEntryIfNewer(hash, Entry{EncryptedLeaseSet: &els}, func(existing Entry) bool {
		return existing.EncryptedLeaseSet == nil || els.PublishedTime().After(existing.EncryptedLeaseSet.PublishedTime())
	}, "EncryptedLeaseSet")

	return els, nil
}

// GetEncryptedLeaseSetBytes retrieves EncryptedLeaseSet data as bytes from the database.
func (db *StdNetDB) GetEncryptedLeaseSetBytes(hash common.Hash) ([]byte, error) {
	return db.getLeaseSetBytesWithHandlers(hash, db.encryptedLeaseSetBytesHandlers())
}

func (db *StdNetDB) encryptedLeaseSetBytesHandlers() leaseSetBytesHandlers {
	return leaseSetBytesHandlers{
		typeName: "EncryptedLeaseSet",
		cacheCheck: func(e Entry) ([]byte, error) {
			if e.EncryptedLeaseSet == nil {
				return nil, nil
			}
			return e.EncryptedLeaseSet.Bytes()
		},
		parseAndCache: func(h common.Hash, d []byte) error {
			_, err := db.parseAndCacheEncryptedLeaseSet(h, d)
			return err
		},
	}
}

// ======================================================================
// MetaLeaseSet Storage and Retrieval Methods
// ======================================================================

// StoreMetaLeaseSet stores a MetaLeaseSet entry in the database from I2NP DatabaseStore message.
// This method validates, parses, caches, and persists MetaLeaseSet data.
// dataType should be 7 for MetaLeaseSet (matching I2P protocol specification).
func (db *StdNetDB) StoreMetaLeaseSet(key common.Hash, data []byte, dataType byte) error {
	var mls meta_leaseset.MetaLeaseSet
	return db.storeLeaseSetVariant(
		key, dataType, metaLeaseSetType, "MetaLeaseSet",
		func() (verifiableLeaseSet, error) {
			var err error
			mls, err = parseMetaLeaseSetData(data)
			if err != nil {
				return nil, err
			}
			if err := verifyMetaLeaseSetHash(key, mls); err != nil {
				return nil, err
			}
			return &mls, nil
		},
		func() bool { return db.addMetaLeaseSetToCache(key, mls) },
		func() error { return db.persistMetaLeaseSetToFilesystem(key, mls) },
	)
}

// parseMetaLeaseSetData parses MetaLeaseSet from raw bytes using the common library.
func parseMetaLeaseSetData(data []byte) (meta_leaseset.MetaLeaseSet, error) {
	mls, _, err := meta_leaseset.ReadMetaLeaseSet(data)
	if err != nil {
		log.WithError(err).Error("Failed to parse MetaLeaseSet from DatabaseStore data")
		return meta_leaseset.MetaLeaseSet{}, oops.Errorf("failed to parse MetaLeaseSet: %w", err)
	}
	return mls, nil
}

// verifyMetaLeaseSetHash validates that the provided key matches the MetaLeaseSet destination hash.
func verifyMetaLeaseSetHash(key common.Hash, mls meta_leaseset.MetaLeaseSet) error {
	return verifyDestinationHashBytes(key, mls.Destination(), "MetaLeaseSet")
}

// addMetaLeaseSetToCache adds a MetaLeaseSet entry to the in-memory cache.
// If an entry already exists, it is replaced only if the new MetaLeaseSet
// has a more recent Published timestamp. Returns true if the entry was added or updated.
func (db *StdNetDB) addMetaLeaseSetToCache(key common.Hash, mls meta_leaseset.MetaLeaseSet) bool {
	expiryTime := mls.ExpirationTime()
	return db.addLeaseSetEntryToCache(key, Entry{MetaLeaseSet: &mls}, func(existing Entry) bool {
		if existing.MetaLeaseSet == nil {
			return true
		}
		return mls.PublishedTime().After(existing.MetaLeaseSet.PublishedTime())
	}, func() { db.lsCache._setExpiryLocked(key, expiryTime) }, "MetaLeaseSet")
}

// persistMetaLeaseSetToFilesystem saves a MetaLeaseSet entry to the filesystem.
func (db *StdNetDB) persistMetaLeaseSetToFilesystem(key common.Hash, mls meta_leaseset.MetaLeaseSet) error {
	return db.persistLeaseSetEntryToFile(key, &Entry{MetaLeaseSet: &mls}, "MetaLeaseSet")
}

// GetMetaLeaseSet retrieves a MetaLeaseSet from the database by its hash.
// Returns a channel that yields the MetaLeaseSet or nil if not found.
// Checks memory cache first, then loads from filesystem if necessary.
func (db *StdNetDB) GetMetaLeaseSet(hash common.Hash) (chnl chan meta_leaseset.MetaLeaseSet) {
	return getLeaseSetVariant(hash, leaseSetVariantGetter[meta_leaseset.MetaLeaseSet]{
		typeName: "MetaLeaseSet",
		cacheLookup: func(hash common.Hash) (meta_leaseset.MetaLeaseSet, bool) {
			db.lsCache.mu.RLock()
			defer db.lsCache.mu.RUnlock()

			entry, ok := db.lsCache.entries[hash]
			if !ok || entry.MetaLeaseSet == nil {
				return meta_leaseset.MetaLeaseSet{}, false
			}

			if db.isLeaseSetExpired(hash) {
				log.WithField("hash", hash).Debug("MetaLeaseSet expired, not serving from cache")
				return meta_leaseset.MetaLeaseSet{}, false
			}

			log.WithFields(logger.Fields{"at": "GetMetaLeaseSet"}).Debug("MetaLeaseSet found in memory cache")
			return *entry.MetaLeaseSet, true
		},
		load: func(hash common.Hash) (meta_leaseset.MetaLeaseSet, error) {
			data, err := db.loadLeaseSetFromFile(hash)
			if err != nil {
				log.WithError(err).Error("Failed to load MetaLeaseSet from file")
				return meta_leaseset.MetaLeaseSet{}, err
			}

			mls, err := db.parseAndCacheMetaLeaseSet(hash, data)
			if err != nil {
				log.WithError(err).Error("Failed to parse MetaLeaseSet")
				return meta_leaseset.MetaLeaseSet{}, err
			}

			return mls, nil
		},
	})
}

// parseAndCacheMetaLeaseSet parses MetaLeaseSet data and adds it to the memory cache.
// If a cached entry already exists, the new entry replaces it only if it has a
// newer published timestamp, preventing stale data from persisting.
//
// CRITICAL-2 FIX: Added cryptographic signature verification before caching.
// MetaLeaseSet must be verified against its signature to prevent attacks where
// persisted files are corrupted to inject malicious data.
func (db *StdNetDB) parseAndCacheMetaLeaseSet(hash common.Hash, data []byte) (meta_leaseset.MetaLeaseSet, error) {
	mls, _, err := meta_leaseset.ReadMetaLeaseSet(data)
	if err != nil {
		return meta_leaseset.MetaLeaseSet{}, oops.Errorf("failed to parse MetaLeaseSet: %w", err)
	}

	// CRITICAL-2 FIX: Verify signature before accepting into cache
	// This is fail-closed: any signature verification failure is rejected completely
	if err := mls.Verify(); err != nil {
		log.WithError(err).WithField("hash", hash).Warn("MetaLeaseSet signature verification failed during retrieval")
		return meta_leaseset.MetaLeaseSet{}, oops.Errorf("MetaLeaseSet signature verification failed: %w", err)
	}

	db.cacheLeaseSetEntryIfNewer(hash, Entry{MetaLeaseSet: &mls}, func(existing Entry) bool {
		return existing.MetaLeaseSet == nil || mls.PublishedTime().After(existing.MetaLeaseSet.PublishedTime())
	}, "MetaLeaseSet")

	return mls, nil
}

// GetMetaLeaseSetBytes retrieves MetaLeaseSet data as bytes from the database.
func (db *StdNetDB) GetMetaLeaseSetBytes(hash common.Hash) ([]byte, error) {
	return db.getLeaseSetBytesWithHandlers(hash, db.metaLeaseSetBytesHandlers())
}

func (db *StdNetDB) metaLeaseSetBytesHandlers() leaseSetBytesHandlers {
	return leaseSetBytesHandlers{
		typeName: "MetaLeaseSet",
		cacheCheck: func(e Entry) ([]byte, error) {
			if e.MetaLeaseSet == nil {
				return nil, nil
			}
			return e.MetaLeaseSet.Bytes()
		},
		parseAndCache: func(h common.Hash, d []byte) error {
			_, err := db.parseAndCacheMetaLeaseSet(h, d)
			return err
		},
	}
}

// ======================================================================
// LeaseSet Expiration Tracking and Cleanup
// ======================================================================

// isLeaseSetExpired checks if the LeaseSet identified by hash has expired
// according to the tracked expiration time. Returns true if expired, false
// if not expired or no expiration is tracked.
func (db *StdNetDB) isLeaseSetExpired(hash common.Hash) bool {
	return db.lsCache.isExpired(hash, time.Now())
}

// trackLeaseSetExpiration extracts the expiration time from a LeaseSet and records it.
// Uses the NewestExpiration() method to find the latest expiration time among all leases.
// If lockHeld is true, assumes the caller already holds db.lsCache.mu lock and uses the unlocked variant.
func (db *StdNetDB) trackLeaseSetExpiration(key common.Hash, ls lease_set.LeaseSet) {
	db.trackLeaseSetExpirationLocked(key, ls, false)
}

// trackLeaseSetExpirationLocked extracts the expiration time from a LeaseSet and records it.
// If lockHeld is true, uses the unlocked setExpiry variant (assumes caller holds the lock).
func (db *StdNetDB) trackLeaseSetExpirationLocked(key common.Hash, ls lease_set.LeaseSet, lockHeld bool) {
	// Get the newest expiration time from all leases in the LeaseSet
	expiration, err := ls.NewestExpiration()
	if err != nil {
		log.WithError(err).WithField("hash", key).Warn("Failed to get LeaseSet expiration, using default 10 minutes")
		// Default to 10 minutes from now if we can't determine expiration
		expiryTime := time.Now().Add(10 * time.Minute)
		if lockHeld {
			db.lsCache._setExpiryLocked(key, expiryTime)
		} else {
			db.lsCache.setExpiry(key, expiryTime)
		}
		return
	}

	expiryTime := expiration.Time()
	if lockHeld {
		db.lsCache._setExpiryLocked(key, expiryTime)
	} else {
		db.lsCache.setExpiry(key, expiryTime)
	}

	log.WithFields(logger.Fields{
		"hash":       logutil.HashPrefix(key),
		"expiration": expiryTime,
		"ttl":        time.Until(expiryTime).Round(time.Second),
	}).Debug("Tracked LeaseSet expiration")
}

// trackLeaseSet2Expiration extracts the expiration time from a LeaseSet2 and records it.
// Uses the ExpirationTime() method to get the expiration timestamp.
func (db *StdNetDB) trackLeaseSet2Expiration(key common.Hash, ls2 lease_set2.LeaseSet2) {
	expiryTime := ls2.ExpirationTime()
	db.lsCache.setExpiry(key, expiryTime)

	log.WithFields(logger.Fields{
		"hash":       logutil.HashPrefix(key),
		"expiration": expiryTime,
		"ttl":        time.Until(expiryTime).Round(time.Second),
	}).Debug("Tracked LeaseSet2 expiration")
}

// trackEncryptedLeaseSetExpiration extracts the expiration time from an EncryptedLeaseSet and records it.
// Uses the ExpirationTime() method to get the expiration timestamp.
func (db *StdNetDB) trackEncryptedLeaseSetExpiration(key common.Hash, els encrypted_leaseset.EncryptedLeaseSet) {
	expiryTime := els.ExpirationTime()
	db.lsCache.setExpiry(key, expiryTime)

	log.WithFields(logger.Fields{
		"hash":       logutil.HashPrefix(key),
		"expiration": expiryTime,
		"ttl":        time.Until(expiryTime).Round(time.Second),
	}).Debug("Tracked EncryptedLeaseSet expiration")
}

// trackMetaLeaseSetExpiration extracts the expiration time from a MetaLeaseSet and records it.
// Uses the ExpirationTime() method to get the expiration timestamp.
func (db *StdNetDB) trackMetaLeaseSetExpiration(key common.Hash, mls meta_leaseset.MetaLeaseSet) {
	expiryTime := mls.ExpirationTime()
	db.lsCache.setExpiry(key, expiryTime)

	log.WithFields(logger.Fields{
		"hash":       logutil.HashPrefix(key),
		"expiration": expiryTime,
		"ttl":        time.Until(expiryTime).Round(time.Second),
	}).Debug("Tracked MetaLeaseSet expiration")
}

// StartExpirationCleaner starts a background goroutine that periodically removes expired LeaseSets
// and prunes stale peer tracking entries.
// The cleanup runs every minute for LeaseSets and every 10 minutes for peer tracking.
// This method should be called once during NetDB initialization.
// Use Stop() to gracefully shut down the cleanup goroutine.
func (db *StdNetDB) StartExpirationCleaner() {
	log.WithFields(logger.Fields{"at": "StartExpirationCleaner"}).Info("Starting expiration cleaner (LeaseSets every 1 min, RouterInfos every 10 min)")

	db.cleanupWg.Add(1)
	go func() {
		defer db.cleanupWg.Done()

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		tickCount := 0

		for {
			select {
			case <-ticker.C:
				db.cleanExpiredLeaseSets()
				tickCount++
				db.runPeriodicMaintenance(tickCount)
			case <-db.ctx.Done():
				log.WithFields(logger.Fields{"at": "StartExpirationCleaner"}).Info("Stopping expiration cleaner")
				return
			}
		}
	}()
}

// runPeriodicMaintenance performs less-frequent cleanup tasks every 10 ticks.
// This includes RouterInfo expiration, peer tracker pruning, and refresh cooldown sweeping.
func (db *StdNetDB) runPeriodicMaintenance(tickCount int) {
	if tickCount%10 != 0 {
		return
	}

	db.cleanExpiredRouterInfos()
	db.pruneStalePeerEntries()
	db.sweepRefreshCooldown()
}

// pruneStalePeerEntries removes peer tracking entries older than 24 hours.
func (db *StdNetDB) pruneStalePeerEntries() {
	if db.PeerTracker == nil {
		return
	}

	const peerMaxAge = 24 * time.Hour
	pruned := db.PeerTracker.PruneOldEntries(peerMaxAge)
	if pruned > 0 {
		log.WithFields(logger.Fields{
			"pruned": pruned,
		}).Info("Pruned stale peer tracker entries")
	}
}

// Stop gracefully shuts down the expiration cleaner goroutine.
// Blocks until the cleanup goroutine has exited.
func (db *StdNetDB) Stop() {
	if db.cancel != nil {
		log.WithFields(logger.Fields{"at": "Stop"}).Info("Stopping StdNetDB")
		db.cancel()
		db.cleanupWg.Wait()
		log.WithFields(logger.Fields{"at": "Stop"}).Info("StdNetDB stopped")
	}
}

// cleanExpiredLeaseSets removes LeaseSets that have passed their expiration time.
// This method is called periodically by the expiration cleaner goroutine.
// It removes entries from both the in-memory cache and the filesystem.
func (db *StdNetDB) cleanExpiredLeaseSets() {
	now := time.Now()

	// Find all expired LeaseSets
	db.lsCache.mu.RLock()
	expired := make([]common.Hash, 0)
	for hash, expiryTime := range db.lsCache.expiry {
		if now.After(expiryTime) {
			expired = append(expired, hash)
		}
	}
	db.lsCache.mu.RUnlock()

	if len(expired) == 0 {
		return
	}

	// Remove expired entries
	for _, hash := range expired {
		db.removeExpiredLeaseSet(hash)
	}

	log.WithFields(logger.Fields{
		"count": len(expired),
		"time":  now.Format(time.RFC3339),
	}).Info("Cleaned expired LeaseSets from NetDB")
}

// removeExpiredLeaseSet removes a single expired LeaseSet from cache and filesystem.
// Both the data map and expiry map are updated atomically (holding both locks)
// to prevent a TOCTOU race where a concurrent store could re-add the entry
// between the two deletions, creating an orphaned entry.
// Lock ordering: lsMutex before expiryMutex to prevent deadlocks.
func (db *StdNetDB) removeExpiredLeaseSet(hash common.Hash) {
	// Remove from cache (already holds necessary locks internally)
	db.lsCache.delete(hash)
	db.lsCache.deleteExpiry(hash)

	// Remove from filesystem (orphaned files self-heal on restart)
	db.removeLeaseSetFromDisk(hash)

	log.WithField("hash", logutil.HashPrefix(hash)).Debug("Removed expired LeaseSet")
}

// removeLeaseSetFromDisk deletes the LeaseSet file from the filesystem.
func (db *StdNetDB) removeLeaseSetFromDisk(hash common.Hash) {
	fpath := db.SkiplistFileForLeaseSet(hash)
	if err := os.Remove(fpath); err != nil {
		if !os.IsNotExist(err) {
			log.WithError(err).WithField("path", fpath).Warn("Failed to remove LeaseSet file")
		}
	}
}

// GetLeaseSetExpirationStats returns statistics about LeaseSet expiration tracking.
// Returns total count, expired count, and time until next expiration.
func (db *StdNetDB) GetLeaseSetExpirationStats() (total, expired int, nextExpiry time.Duration) {
	db.lsCache.mu.RLock()
	defer db.lsCache.mu.RUnlock()
	return computeExpirationStats(db.lsCache.expiry)
}

// GetAllLeaseSets returns all LeaseSets currently stored in the database.
// This includes all types: LeaseSet, LeaseSet2, EncryptedLeaseSet, and MetaLeaseSet.
// The method returns a slice of LeaseSetEntry containing the hash and Entry data.
// This is primarily used for publishing all LeaseSets to floodfill routers.
func (db *StdNetDB) GetAllLeaseSets() []LeaseSetEntry {
	log.WithFields(logger.Fields{"at": "GetAllLeaseSets"}).Debug("Getting all LeaseSets from database")

	db.lsCache.mu.RLock()
	defer db.lsCache.mu.RUnlock()

	// Pre-allocate slice with capacity to avoid reallocation
	result := make([]LeaseSetEntry, 0, len(db.lsCache.entries))

	// Iterate through all cached LeaseSets
	for hash, entry := range db.lsCache.entries {
		result = append(result, LeaseSetEntry{
			Hash:  hash,
			Entry: entry,
		})
	}

	log.WithField("count", len(result)).Debug("Retrieved all LeaseSets")
	return result
}

// GetPublicLeaseSets returns only LeaseSets that are NOT marked as "own-created".
// This excludes session-created LeaseSets that should not be served to external lookups.
// Used by FloodfillServer to answer external database lookup queries privately.
func (db *StdNetDB) GetPublicLeaseSets() []LeaseSetEntry {
	db.lsCache.mu.RLock()
	db.ownLeaseSetsMu.RLock()
	defer func() {
		db.ownLeaseSetsMu.RUnlock()
		db.lsCache.mu.RUnlock()
	}()

	result := make([]LeaseSetEntry, 0)

	// Iterate through all cached LeaseSets and skip those marked as own-created
	for hash, entry := range db.lsCache.entries {
		if !db.ownLeaseSets[hash] {
			result = append(result, LeaseSetEntry{
				Hash:  hash,
				Entry: entry,
			})
		}
	}

	log.WithField("count", len(result)).Debug("Retrieved public LeaseSets")
	return result
}

// StoreOwnLeaseSet stores a session-created LeaseSet for local use only.
// The LeaseSet is stored in the cache and marked as "own-created" so it will NOT
// be served to external lookup queries. This maintains privacy by only serving
// LeaseSets that would have normally reached us through network propagation.
// Used by Publisher for I2CP session-created LeaseSets.
func (db *StdNetDB) StoreOwnLeaseSet(key common.Hash, data []byte, dataType byte) error {
	// First, try to store it like a normal LeaseSet (parsing and validation)
	if err := db.StoreLeaseSet(key, data, dataType); err != nil {
		return err
	}

	// Mark it as own-created for privacy
	db.ownLeaseSetsMu.Lock()
	db.ownLeaseSets[key] = true
	db.ownLeaseSetsMu.Unlock()

	log.WithFields(logger.Fields{
		"hash": logutil.HashPrefixPlain(key),
		"at":   "StoreOwnLeaseSet",
	}).Debug("Stored own-created LeaseSet (local-use-only)")

	return nil
}

// IsOwnLeaseSet checks if a LeaseSet was created locally by this router's I2CP session.
// Own LeaseSets are not served to external lookup queries.
// Returns true if the hash is marked as own-created, false otherwise.
func (db *StdNetDB) IsOwnLeaseSet(hash common.Hash) bool {
	db.ownLeaseSetsMu.RLock()
	defer db.ownLeaseSetsMu.RUnlock()
	return db.ownLeaseSets[hash]
}
