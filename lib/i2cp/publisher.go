package i2cp

import (
	common "github.com/go-i2p/common/data"
)

// LeaseSetPublisher defines the interface for publishing LeaseSets to the network.
// This interface allows I2CP sessions to publish their LeaseSets without depending
// directly on the router or netdb implementations.
//
// Implementations should:
// - Store the LeaseSet in the local NetDB
// - Send DatabaseStore messages to floodfill routers for network distribution
// - Handle any errors during the publication process
type LeaseSetPublisher interface {
	// PublishLeaseSet publishes a LeaseSet to the network database and distributed network.
	//
	// Parameters:
	//   - key: The destination hash (SHA256 of the destination)
	//   - leaseSetData: The serialized LeaseSet2 bytes
	//
	// Returns an error if publication fails at any stage (local storage or network distribution).
	PublishLeaseSet(key common.Hash, leaseSetData []byte) error
}
