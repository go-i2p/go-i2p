package netdb

import (
	"fmt"
	"os"
	"time"

	"github.com/go-i2p/logger"

	common "github.com/go-i2p/common/data"
)

// RouterInfoMaxAge defines the maximum age for a RouterInfo before it is considered stale.
// Per the I2P specification, RouterInfos are typically considered stale after about 27 hours,
// though some implementations use longer thresholds. We use 48 hours to be conservative
// and reduce unnecessary churn during periods of intermittent connectivity.
const RouterInfoMaxAge = 48 * time.Hour

// RouterInfoCleanupInterval defines how often the RouterInfo expiration cleaner runs.
// RouterInfos change less frequently than LeaseSets, so a 10-minute interval is sufficient.
const RouterInfoCleanupInterval = 10 * time.Minute

// MinRouterInfoCount is the minimum number of RouterInfos to keep in the NetDB
// even if they are expired. This prevents the NetDB from becoming empty during
// periods of poor connectivity or clock skew, which would prevent re-bootstrapping.
const MinRouterInfoCount = 25

// trackRouterInfoExpiration records when a RouterInfo was published so the expiration
// cleaner can remove it when it becomes stale. The expiration time is calculated as
// the RouterInfo's published date plus RouterInfoMaxAge.
func (db *StdNetDB) trackRouterInfoExpiration(key common.Hash, publishedTime time.Time) {
	expiryTime := publishedTime.Add(RouterInfoMaxAge)

	db.expiryMutex.Lock()
	db.routerInfoExpiry[key] = expiryTime
	db.expiryMutex.Unlock()

	log.WithFields(logger.Fields{
		"hash":       fmt.Sprintf("%x", key[:8]),
		"published":  publishedTime.Format(time.RFC3339),
		"expiration": expiryTime.Format(time.RFC3339),
		"ttl":        time.Until(expiryTime).Round(time.Second),
	}).Debug("Tracked RouterInfo expiration")
}

// cleanExpiredRouterInfos removes RouterInfos that have exceeded their maximum age.
// It preserves at least MinRouterInfoCount entries to prevent the NetDB from becoming
// empty, which would prevent the router from functioning.
func (db *StdNetDB) cleanExpiredRouterInfos() {
	now := time.Now()

	// Find all expired RouterInfos
	db.expiryMutex.RLock()
	expired := make([]common.Hash, 0)
	for hash, expiryTime := range db.routerInfoExpiry {
		if now.After(expiryTime) {
			expired = append(expired, hash)
		}
	}
	db.expiryMutex.RUnlock()

	if len(expired) == 0 {
		return
	}

	// Check if removing all expired entries would bring us below the minimum count
	db.riMutex.RLock()
	currentCount := len(db.RouterInfos)
	db.riMutex.RUnlock()

	// Only remove entries that keep us above the minimum threshold
	maxRemovable := currentCount - MinRouterInfoCount
	if maxRemovable <= 0 {
		log.WithFields(logger.Fields{
			"expired_count": len(expired),
			"current_count": currentCount,
			"min_count":     MinRouterInfoCount,
		}).Debug("Skipping RouterInfo expiration: at or below minimum count")
		return
	}

	// If we can't remove all expired entries, limit the removal count
	removeCount := len(expired)
	if removeCount > maxRemovable {
		removeCount = maxRemovable
	}

	// Remove the expired entries (up to the allowed limit)
	removed := 0
	for _, hash := range expired {
		if removed >= removeCount {
			break
		}
		db.removeExpiredRouterInfo(hash)
		removed++
	}

	if removed > 0 {
		log.WithFields(logger.Fields{
			"removed":        removed,
			"total_expired":  len(expired),
			"remaining_size": currentCount - removed,
		}).Info("Cleaned expired RouterInfos from NetDB")
	}
}

// removeExpiredRouterInfo removes a single expired RouterInfo from cache, filesystem,
// and expiry tracking. The removal order is: data map first (so readers stop finding it),
// then expiry tracking, then disk. This ordering prevents a TOCTOU race where a reader
// could find the entry in the data map but find it missing from the expiry map.
func (db *StdNetDB) removeExpiredRouterInfo(hash common.Hash) {
	// Remove from memory cache first so readers stop finding it
	db.riMutex.Lock()
	delete(db.RouterInfos, hash)
	db.riMutex.Unlock()

	// Remove from expiry tracking
	db.expiryMutex.Lock()
	delete(db.routerInfoExpiry, hash)
	db.expiryMutex.Unlock()

	// Remove from filesystem (orphaned files self-heal on restart)
	db.removeRouterInfoFromDisk(hash)

	log.WithField("hash", fmt.Sprintf("%x", hash[:8])).Debug("Removed expired RouterInfo")
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

// GetRouterInfoExpirationStats returns statistics about RouterInfo expiration tracking.
// Returns total tracked count, expired count, and time until next expiration.
func (db *StdNetDB) GetRouterInfoExpirationStats() (total, expired int, nextExpiry time.Duration) {
	now := time.Now()
	var earliest time.Time

	db.expiryMutex.RLock()
	defer db.expiryMutex.RUnlock()

	total = len(db.routerInfoExpiry)
	for _, expiryTime := range db.routerInfoExpiry {
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
