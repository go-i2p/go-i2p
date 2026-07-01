package netdb

import (
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
)

const (
	routerInfoPersistRetryBaseDelay = 1 * time.Minute
	routerInfoPersistRetryMaxDelay  = 30 * time.Minute
)

type routerInfoPersistRetryState struct {
	attempts    int
	nextAttempt time.Time
	lastError   string
}

func computeRouterInfoPersistRetryDelay(attempt int) time.Duration {
	if attempt <= 1 {
		return routerInfoPersistRetryBaseDelay
	}
	delay := routerInfoPersistRetryBaseDelay
	for i := 2; i <= attempt; i++ {
		delay *= 2
		if delay >= routerInfoPersistRetryMaxDelay {
			return routerInfoPersistRetryMaxDelay
		}
	}
	return delay
}

func (db *StdNetDB) scheduleRouterInfoPersistRetry(hash common.Hash, persistErr error, fromRetry bool) {
	now := time.Now()
	errText := "unknown"
	if persistErr != nil {
		errText = persistErr.Error()
	}

	db.persistMu.Lock()
	state := db.pendingRouterInfoPersists[hash]
	state.attempts++
	state.nextAttempt = now.Add(computeRouterInfoPersistRetryDelay(state.attempts))
	state.lastError = errText
	db.pendingRouterInfoPersists[hash] = state
	pending := len(db.pendingRouterInfoPersists)
	db.persistMu.Unlock()

	if fromRetry {
		db.routerInfoStoreStats.persistRetryFailureCount.Add(1)
	} else {
		db.routerInfoStoreStats.persistDeferredCount.Add(1)
	}

	log.WithFields(logger.Fields{
		"hash":         logutil.HashPrefix(hash),
		"attempt":      state.attempts,
		"next_attempt": state.nextAttempt.Format(time.RFC3339),
		"pending":      pending,
		"error":        errText,
	}).Warn("RouterInfo persisted in memory; scheduled filesystem persistence retry")
}

func (db *StdNetDB) retryPendingRouterInfoPersists() {
	now := time.Now()
	toRetry := make([]common.Hash, 0)

	db.persistMu.Lock()
	for hash, state := range db.pendingRouterInfoPersists {
		if !state.nextAttempt.After(now) {
			toRetry = append(toRetry, hash)
		}
	}
	db.persistMu.Unlock()

	for _, hash := range toRetry {
		entry, exists := db.riCache.get(hash)
		if !exists || entry.RouterInfo == nil {
			db.persistMu.Lock()
			delete(db.pendingRouterInfoPersists, hash)
			db.persistMu.Unlock()
			continue
		}

		if err := db.SaveEntry(&Entry{RouterInfo: entry.RouterInfo}); err != nil {
			db.scheduleRouterInfoPersistRetry(hash, err, true)
			continue
		}

		db.persistMu.Lock()
		delete(db.pendingRouterInfoPersists, hash)
		pending := len(db.pendingRouterInfoPersists)
		db.persistMu.Unlock()
		db.routerInfoStoreStats.persistRetrySuccessCount.Add(1)

		log.WithFields(logger.Fields{
			"hash":    logutil.HashPrefix(hash),
			"pending": pending,
		}).Info("RouterInfo filesystem persistence retry succeeded")
	}
}
