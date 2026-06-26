package netdb

import (
	"crypto/sha256"
	"strings"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
)

// RoutingKey derives the I2P routing key for a given hash on the given UTC date.
//
// Per the I2P spec (Common Structures / NetDB Routing Key):
//
//	routing_key = SHA256(hash || date)
//
// where date is the UTC calendar date formatted as "yyyyMMdd" (e.g. "20260626").
// This mapping changes every midnight UTC, so publish and lookup must always use
// the same (current) date or the data will be stored at and queried from entirely
// different floodfill nodes.
//
// Note: this returns a [32]byte identical in length to common.Hash so callers can
// pass it directly to SelectFloodfillRouters / XOR-distance calculations.
func RoutingKey(h common.Hash, now time.Time) common.Hash {
	date := now.UTC().Format("20060102") // Go reference time equivalent of yyyyMMdd
	sum := sha256.Sum256(append(h[:], []byte(date)...))
	return sum
}

// CalculateXORDistance calculates the XOR distance between two hashes.
// XOR distance is the bitwise XOR of the two hashes, used in Kademlia DHT.
// This is the canonical implementation — all other XOR distance calculations
// in the package delegate to this function.
func CalculateXORDistance(hash1, hash2 common.Hash) []byte {
	distance := make([]byte, len(hash1))
	for i := 0; i < len(hash1); i++ {
		distance[i] = hash1[i] ^ hash2[i]
	}
	return distance
}

// CompareXORDistances compares two XOR distances using big-endian byte comparison.
// Returns true if dist1 < dist2 (dist1 is closer).
// This is the canonical implementation for XOR distance comparison.
func CompareXORDistances(dist1, dist2 []byte) bool {
	for i := 0; i < len(dist1); i++ {
		if dist1[i] < dist2[i] {
			return true
		}
		if dist1[i] > dist2[i] {
			return false
		}
	}
	return false // Equal distances
}

// IsFloodfillRouter checks if a RouterInfo represents a floodfill router.
// Returns true if the router's "caps" option contains 'f'.
// This is the canonical implementation — all floodfill detection should use this.
func IsFloodfillRouter(ri router_info.RouterInfo) bool {
	options := ri.Options()
	capsKey, _ := common.ToI2PString("caps")
	capsValue := options.Values().Get(capsKey)
	caps, _ := capsValue.Data()
	return strings.Contains(caps, "f")
}
