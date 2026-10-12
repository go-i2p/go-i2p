// Package netdb implements the Network Database (NetDB) for I2P router
// information and lease sets.
//
// # What is the NetDB?
//
// The NetDB is a router's local copy of the I2P network database. It stores
// two kinds of records:
//
//   - RouterInfo: how to reach a router (its addresses, keys, and
//     capabilities).
//   - LeaseSet: how to reach a service (a destination) through the network.
//
// Routers share these records with each other using I2NP DatabaseStore and
// DatabaseLookup messages (see lib/i2np). The NetDB is what a router consults
// to find out where to send traffic.
//
// RouterInfo and LeaseSet are defined in the common structures specification:
// https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/common-structures.rst
//
// # Storage architecture
//
// The package uses a hybrid storage approach:
//   - An in-memory cache for fast lookups.
//   - Filesystem persistence using a skiplist structure.
//   - Automatic expiration and cleanup of stale entries.
//
// # Thread safety
//
// StdNetDB is safe for concurrent use:
//   - RouterInfo and LeaseSet maps have separate mutexes.
//   - Expiry tracking uses a read-write mutex for efficiency.
//   - Background cleanup runs in a separate goroutine.
//
// # Usage example
//
//	// Create a NetDB.
//	db := netdb.NewStdNetDB("/path/to/netdb")
//	if err := db.Create(); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Store a RouterInfo.
//	hash, err := routerInfo.IdentHash()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	data, err := routerInfo.Bytes()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if err := db.StoreRouterInfoFromMessage(hash, data, 0); err != nil {
//	    log.Printf("Failed to store: %v", err)
//	}
//
//	// Retrieve a RouterInfo.
//	riChan := db.GetRouterInfo(hash)
//	if ri, ok := <-riChan; ok {
//	    // Use router info
//	}
//
// # Reseed and bootstrap
//
// The package includes reseed functionality to bootstrap the NetDB with
// initial router information from trusted sources. See the bootstrap package
// for the reseed client implementation.
//
// # Exploration
//
// The Explorer performs periodic database lookups to discover new routers and
// expand the NetDB beyond the floodfill routers. Two strategies are supported:
//
//   - Adaptive (default): targets sparse regions of the keyspace using bucket
//     analysis, so it finds routers in under-represented areas. It adjusts its
//     interval automatically based on NetDB health.
//
//   - Random: performs lookups for random keys across the whole keyspace.
//     Simpler, but less efficient than the adaptive strategy.
//
// Exploration runs in the background with a configurable interval (default: 5
// minutes), concurrency (default: 3 parallel lookups), and timeout (default:
// 30 seconds per lookup).
package netdb
