package router

import (
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/samber/oops"
)

// storeRouterInfoViaSerialization stores a locally-constructed RouterInfo in
// NetDB using the local storage path (raw RouterInfo bytes, not DatabaseStore
// wire payload format).
func storeRouterInfoViaSerialization(db *netdb.StdNetDB, ri router_info.RouterInfo) (err error) {
	if err := db.StoreRouterInfoWithError(ri); err != nil {
		return oops.Errorf("failed to store RouterInfo in NetDB: %w", err)
	}

	return nil
}
