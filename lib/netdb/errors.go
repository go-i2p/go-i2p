package netdb

import "errors"

// ErrNoPeerData is returned when no peer tracking data is available
// for the requested hash in the PeerTracker.
var ErrNoPeerData = errors.New("no peer data available")

// ErrInvalidPeerHash is returned when a peer hash is zero or does not
// match the expected format (32-byte SHA-256 hash).
var ErrInvalidPeerHash = errors.New("invalid peer hash")
