// Package i2np implements the I2P Network Protocol (I2NP) for router-to-router communication.
//
// I2NP defines message types for:
//   - Network database operations (DatabaseStore, DatabaseLookup)
//   - Tunnel building (ShortTunnelBuild, VariableTunnelBuild)
//   - Data delivery (TunnelData, Data, DeliveryStatus)
//   - Garlic encryption (end-to-end encrypted message bundles)
//
// Message structure:
//   - Header: type, ID, expiration, size, checksum
//   - Payload: type-specific data
//
// Cryptography uses ECIES-X25519-AEAD-Ratchet for garlic encryption
// and ChaCha20-Poly1305 for tunnel build records.
//
// DatabaseStore supports RouterInfo, LeaseSet, and LeaseSet2 (type field bits 3-0).
package i2np
