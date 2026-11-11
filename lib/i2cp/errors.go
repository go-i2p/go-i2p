package i2cp

import "errors"

// Sentinel errors for outbound message routing.
//
// The outbound path is fail-closed by design: a message that cannot be
// correctly encapsulated and addressed is dropped with an error rather than
// handed to the transport unprotected. Sending a bare I2NP message to a tunnel
// hop leaks the sender's real IP and the data is discarded by the network
// anyway, so there is no useful "best effort" fallback at that layer.
var (
	// ErrNoLease reports that a destination has no usable lease: no LeaseSet,
	// an invalid one, or only expired leases.
	ErrNoLease = errors.New("no usable lease for destination")

	// errNoLeaseSet2 / errNoLeaseSet1 are internal markers used while trying
	// both lease-set generations before reporting ErrNoLease.
	errNoLeaseSet2 = errors.New("no usable LeaseSet2")
	errNoLeaseSet1 = errors.New("no usable LeaseSet")
	errNoLiveLease = errors.New("lease set has no live lease")
)
