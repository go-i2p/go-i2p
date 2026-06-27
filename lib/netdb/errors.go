package netdb

import "errors"

// ErrNoPeerData is returned when no peer tracking data is available
// for the requested hash in the PeerTracker.
var ErrNoPeerData = errors.New("no peer data available")

// ErrInvalidPeerHash is returned when a peer hash is zero or does not
// match the expected format (32-byte SHA-256 hash).
var ErrInvalidPeerHash = errors.New("invalid peer hash")

// ErrCorruptedProfiles is returned when persisted peer profile data
// cannot be loaded or parsed, typically due to disk corruption or
// incompatible format changes.
var ErrCorruptedProfiles = errors.New("corrupted peer profiles")

// ErrNetDBNotInitialized is returned when an operation requires the
// NetDB to be initialized but it has not been created or started yet.
var ErrNetDBNotInitialized = errors.New("netdb not initialized")
