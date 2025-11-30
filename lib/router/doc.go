// Package router coordinates I2P router subsystems including I2CP server,
// tunnel management, NetDB, transport layer, and message routing.
//
// # Router Architecture
//
// The Router integrates multiple subsystems:
//   - I2CP server for client applications (localhost:7654)
//   - Tunnel pools for anonymized routing
//   - NetDB for RouterInfo and LeaseSet storage
//   - NTCP2 transport for router-to-router communication
//   - Message routing with garlic encryption (ECIES-X25519-AEAD-Ratchet)
//
// # Usage Example
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
// # Current Status
//
// Core routing functional, I2CP complete, LeaseSet2 supported.
package router
