// Package router coordinates the I2P router subsystems: the I2CP server,
// tunnel management, the NetDB, the transport layer, and message routing.
//
// # What is the router?
//
// A router is the main I2P node. It ties all the other packages together and
// runs them as one unit:
//
//   - I2CP server for client applications (localhost:7654).
//   - Tunnel pools for anonymized routing.
//   - NetDB for RouterInfo and LeaseSet storage.
//   - NTCP2 and SSU2 transports for router-to-router communication.
//   - Message routing with garlic encryption (ECIES-X25519-AEAD-Ratchet).
//
// # Usage example
//
//	// Create router
//	router, err := router.NewRouter(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Start router (non-blocking)
//	if err := router.Start(); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Router runs in background...
//
//	// Graceful shutdown
//	if err := router.Stop(); err != nil {
//	    log.Printf("Shutdown error: %v", err)
//	}
//
// # Current status
//
// Core routing is functional, I2CP is complete, and LeaseSet2 is supported.
package router
