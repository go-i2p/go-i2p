package transport

import (
	"crypto/sha256"
	"net"

	"github.com/go-i2p/common/data"
)

// DeriveConnectionHash derives a peer identification hash from a connection.
// It first attempts to extract the hash using the provided extractFunc (which handles
// protocol-specific address types). If extraction succeeds and returns a non-zero hash,
// it's used directly. Otherwise, it derives a fallback hash from the remote address
// using SHA-256, with the address stripped to host-only (without ephemeral port).
// The marker byte distinguishes address-derived keys from real router hashes.
//
// This is used by transport layers (NTCP2, SSU2) for session tracking and peer identification.
func DeriveConnectionHash(conn net.Conn, extractFunc func() (data.Hash, bool), markerByte byte) data.Hash {
	var peerHash data.Hash

	// Try protocol-specific hash extraction first
	if hash, ok := extractFunc(); ok {
		// Check if hash is non-zero
		var zeroHash data.Hash
		if hash != zeroHash {
			return hash
		}
	}

	// SA-3 fix: Fallback for connections without a router hash.
	// Hash the full address with SHA-256 to avoid truncation collisions when
	// address strings exceed 32 bytes (long IPv6 addresses with zones).
	// Set a consistent marker byte to separate address-derived keys from real
	// router hashes, preventing collisions if a router hash happens to match
	// an address-derived key.
	//
	// Strip the ephemeral port so reconnections from the same host produce
	// the same hash, avoiding duplicate session tracking entries.
	addrStr := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(addrStr); err == nil {
		addrStr = host
	}
	hash := sha256.Sum256([]byte(addrStr))
	copy(peerHash[:], hash[:])
	peerHash[0] = markerByte

	return peerHash
}
