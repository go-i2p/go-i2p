// Package netdb implements the Network Database for I2P router information and lease sets.
//
// The NetDB stores and manages:
//   - RouterInfo: Network routing information for I2P routers
//   - LeaseSet: Destination lease information for I2P services
//
// # Storage Architecture
//
// The package uses a hybrid storage approach:
//   - In-memory cache for fast lookups
//   - Filesystem persistence using skiplist structure
//   - Automatic expiration and cleanup of stale entries
//
// # Thread Safety
//
// StdNetDB is safe for concurrent access:
//   - RouterInfo and LeaseSet maps have separate mutexes
//   - Expiry tracking uses read-write mutex for efficiency
//   - Background cleanup runs in separate goroutine
//
// # Usage Example
//
//	// Create NetDB
//	db := netdb.NewStdNetDB("/path/to/netdb")
//	if err := db.Create(); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Store RouterInfo
//	hash, err := routerInfo.IdentHash()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	data, err := routerInfo.Bytes()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if err := db.StoreRouterInfo(hash, data, 0); err != nil {
//	    log.Printf("Failed to store: %v", err)
//	}
//
//	// Retrieve RouterInfo
//	riChan := db.GetRouterInfo(hash)
//	if ri := <-riChan; ri != nil {
//	    // Use router info
//	}
//
// # Reseed and Bootstrap
//
// The package includes reseed functionality to bootstrap the NetDB with
// initial router information from trusted sources.
//
// See bootstrap package for reseed client implementation.
package netdb
