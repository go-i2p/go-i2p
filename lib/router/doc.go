// Package router coordinates I2P router subsystems including I2CP server,
// tunnel management, NetDB, transport layer, and message routing.
//
// The Router integrates:
//   - I2CP server for client applications (localhost:7654)
//   - Tunnel pools for anonymized routing
//   - NetDB for RouterInfo and LeaseSet storage
//   - NTCP2 transport for router-to-router communication
//   - Message routing with garlic encryption (ECIES-X25519-AEAD-Ratchet)
//
// Current status: Core routing functional, I2CP complete, LeaseSet2 supported.
package router
