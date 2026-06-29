package netdb

import (
	"os"
	"time"

	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"

	common "github.com/go-i2p/common/data"
)

// RouterInfoMaxAge defines the maximum age for a RouterInfo before it is considered stale.
// The I2P spec does not specify a universal 27-hour threshold; expiry depends on network size
// (~30h for a ~300-router network). We use 48 hours as a conservative implementation choice
// to reduce unnecessary churn during periods of intermittent connectivity.
const RouterInfoMaxAge = 48 * time.Hour

// RouterInfoCleanupInterval defines how often the RouterInfo expiration cleaner runs.
// RouterInfos change less frequently than LeaseSets, so a 10-minute interval is sufficient.
const RouterInfoCleanupInterval = 10 * time.Minute

// MinRouterInfoCount is the minimum number of RouterInfos to keep in the NetDB
// even if they are expired. This prevents the NetDB from becoming empty during
// periods of poor connectivity or clock skew, which would prevent re-bootstrapping.
const MinRouterInfoCount = 200

// trackRouterInfoExpiration records when a RouterInfo was published so the expiration
// cleaner can remove it when it becomes stale. The expiration time is calculated as
// the RouterInfo's published date plus RouterInfoMaxAge.
func (db *StdNetDB) trackRouterInfoExpiration(key common.Hash, publishedTime time.Time) {
	expiryTime := publishedTime.Add(RouterInfoMaxAge)
	db.riCache.setExpiry(key, expiryTime)

	log.WithFields(logger.Fields{
		"hash":       logutil.HashPrefix(key),
		"published":  publishedTime.Format(time.RFC3339),
		"expiration": expiryTime.Format(time.RFC3339),
		"ttl":        time.Until(expiryTime).Round(time.Second),
	}).Debug("Tracked RouterInfo expiration")
}

// cleanExpiredRouterInfos removes RouterInfos that have exceeded their maximum age.
// It preserves at least MinRouterInfoCount entries to prevent the NetDB from becoming
// empty, which would prevent the router from functioning.
func (db *StdNetDB) cleanExpiredRouterInfos() {
	expired := db.findExpiredRouterInfoHashes()
	if len(expired) == 0 {
		return
	}

	removeCount := db.calculateRemovableCount(len(expired))
	if removeCount <= 0 {
		return
	}

	removed := db.removeRouterInfoBatch(expired, removeCount)

	if removed > 0 {
		remaining := db.riCache.count()
		log.WithFields(logger.Fields{
			"removed":        removed,
			"total_expired":  len(expired),
			"remaining_size": remaining,
		}).Info("Cleaned expired RouterInfos from NetDB")
	}
}

// findExpiredRouterInfoHashes returns the hashes of all RouterInfos whose expiry time has passed.
func (db *StdNetDB) findExpiredRouterInfoHashes() []common.Hash {
	now := time.Now()
	db.riCache.mu.RLock()
	expired := make([]common.Hash, 0)
	for hash, expiryTime := range db.riCache.expiry {
		if now.After(expiryTime) {
			expired = append(expired, hash)
		}
	}
	db.riCache.mu.RUnlock()
	return expired
}

// calculateRemovableCount determines how many expired entries can be removed
// while keeping at least MinRouterInfoCount entries in the database.
// Returns 0 if no entries should be removed.
func (db *StdNetDB) calculateRemovableCount(expiredCount int) int {
	currentCount := db.riCache.count()

	maxRemovable := currentCount - MinRouterInfoCount
	if maxRemovable <= 0 {
		log.WithFields(logger.Fields{
			"expired_count": expiredCount,
			"current_count": currentCount,
			"min_count":     MinRouterInfoCount,
		}).Debug("Skipping RouterInfo expiration: at or below minimum count")
		return 0
	}

	if expiredCount > maxRemovable {
		return maxRemovable
	}
	return expiredCount
}

// removeRouterInfoBatch removes up to limit expired RouterInfos from the database.
// Returns the number of entries actually removed.
func (db *StdNetDB) removeRouterInfoBatch(expired []common.Hash, limit int) int {
	removed := 0
	for _, hash := range expired {
		if removed >= limit {
			break
		}
		db.removeExpiredRouterInfo(hash)
		removed++
	}
	return removed
}

// removeExpiredRouterInfo removes a single expired RouterInfo from cache, filesystem,
// and expiry tracking. The removal order is: data map first (so readers stop finding it),
// then expiry tracking, then disk. This ordering prevents a TOCTOU race where a reader
// could find the entry in the data map but find it missing from the expiry map.
func (db *StdNetDB) removeExpiredRouterInfo(hash common.Hash) {
	// Remove from memory cache first so readers stop finding it
	db.riCache.delete(hash)

	// Remove from expiry tracking
	db.riCache.deleteExpiry(hash)

	// Remove from filesystem (orphaned files self-heal on restart)
	db.removeRouterInfoFromDisk(hash)

	log.WithField("hash", logutil.HashPrefix(hash)).Debug("Removed expired RouterInfo")
}

// removeRouterInfoFromDisk deletes the RouterInfo file from the filesystem.
func (db *StdNetDB) removeRouterInfoFromDisk(hash common.Hash) {
	fpath := db.SkiplistFile(hash)
	if err := os.Remove(fpath); err != nil {
		if !os.IsNotExist(err) {
			log.WithError(err).WithField("path", fpath).Warn("Failed to remove RouterInfo file")
		}
	}
}

// computeExpirationStats calculates stats over a time-keyed expiry map.
// Returns the total count, how many are expired, and the time until the next expiration.
// The caller must hold the appropriate read lock.
func computeExpirationStats(expiryMap map[common.Hash]time.Time) (total, expired int, nextExpiry time.Duration) {
	now := time.Now()
	var earliest time.Time

	total = len(expiryMap)
	for _, expiryTime := range expiryMap {
		if now.After(expiryTime) {
			expired++
		} else if earliest.IsZero() || expiryTime.Before(earliest) {
			earliest = expiryTime
		}
	}

	if !earliest.IsZero() {
		nextExpiry = time.Until(earliest)
	}

	return total, expired, nextExpiry
}

// GetRouterInfoExpirationStats returns statistics about RouterInfo expiration tracking.
// Returns total tracked count, expired count, and time until next expiration.
func (db *StdNetDB) GetRouterInfoExpirationStats() (total, expired int, nextExpiry time.Duration) {
	db.riCache.mu.RLock()
	defer db.riCache.mu.RUnlock()
	return computeExpirationStats(db.riCache.expiry)
}
