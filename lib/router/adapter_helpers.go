package router

import (
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/samber/oops"
)

// storeRouterInfoViaSerialization converts a RouterInfo to bytes and stores it in the NetDB.
// This encapsulates the common 3-step pattern: IdentHash → Bytes → StoreRouterInfoFromMessage
// Used by both publisherNetDBAdapter and netDBAdapter to avoid duplication.
func storeRouterInfoViaSerialization(db *netdb.StdNetDB, ri router_info.RouterInfo) (err error) {
	// Step 1: Get the identity hash from the RouterInfo
	hash, err := ri.IdentHash()
	if err != nil {
		return oops.Errorf("failed to get identity hash from RouterInfo: %w", err)
	}

	// Step 2: Serialize the RouterInfo to bytes
	data, err := ri.Bytes()
	if err != nil {
		return oops.Errorf("failed to serialize RouterInfo: %w", err)
	}

	// Step 3: Store in NetDB
	if err := db.StoreRouterInfoFromMessage(hash, data, 0); err != nil {
		return oops.Errorf("failed to store RouterInfo in NetDB (hash=%s): %w", hash.String(), err)
	}

	return nil
}
