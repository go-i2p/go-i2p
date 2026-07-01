package netdb

import "sync/atomic"

// RouterInfoStoreStats provides observability for RouterInfo intake and
// persistence outcomes.
type RouterInfoStoreStats struct {
	AcceptedCount            uint64
	RejectedDataTypeCount    uint64
	RejectedParseCount       uint64
	RejectedValidationCount  uint64
	RejectedHashCount        uint64
	RejectedSignatureCount   uint64
	RejectedNetworkCount     uint64
	RejectedAdmissionCount   uint64
	DuplicateOrStaleCount    uint64
	PersistDeferredCount     uint64
	PersistRetrySuccessCount uint64
	PersistRetryFailureCount uint64
	PersistPendingCount      uint64
}

type routerInfoStoreStats struct {
	acceptedCount            atomic.Uint64
	rejectedDataTypeCount    atomic.Uint64
	rejectedParseCount       atomic.Uint64
	rejectedValidationCount  atomic.Uint64
	rejectedHashCount        atomic.Uint64
	rejectedSignatureCount   atomic.Uint64
	rejectedNetworkCount     atomic.Uint64
	rejectedAdmissionCount   atomic.Uint64
	duplicateOrStaleCount    atomic.Uint64
	persistDeferredCount     atomic.Uint64
	persistRetrySuccessCount atomic.Uint64
	persistRetryFailureCount atomic.Uint64
}

func (s *routerInfoStoreStats) snapshot(pending uint64) RouterInfoStoreStats {
	return RouterInfoStoreStats{
		AcceptedCount:            s.acceptedCount.Load(),
		RejectedDataTypeCount:    s.rejectedDataTypeCount.Load(),
		RejectedParseCount:       s.rejectedParseCount.Load(),
		RejectedValidationCount:  s.rejectedValidationCount.Load(),
		RejectedHashCount:        s.rejectedHashCount.Load(),
		RejectedSignatureCount:   s.rejectedSignatureCount.Load(),
		RejectedNetworkCount:     s.rejectedNetworkCount.Load(),
		RejectedAdmissionCount:   s.rejectedAdmissionCount.Load(),
		DuplicateOrStaleCount:    s.duplicateOrStaleCount.Load(),
		PersistDeferredCount:     s.persistDeferredCount.Load(),
		PersistRetrySuccessCount: s.persistRetrySuccessCount.Load(),
		PersistRetryFailureCount: s.persistRetryFailureCount.Load(),
		PersistPendingCount:      pending,
	}
}

// GetRouterInfoStoreStats returns counters that characterize RouterInfo ingest
// acceptance/rejection and deferred persistence health.
func (db *StdNetDB) GetRouterInfoStoreStats() RouterInfoStoreStats {
	db.persistMu.Lock()
	pending := uint64(len(db.pendingRouterInfoPersists))
	db.persistMu.Unlock()
	return db.routerInfoStoreStats.snapshot(pending)
}
