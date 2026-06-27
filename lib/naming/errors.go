package naming

import "errors"

// ErrHostnameNotFound is returned when a hostname is not found in the
// resolver's hosts map.
var ErrHostnameNotFound = errors.New("hostname not found")

// ErrEmptyHostname is returned when an empty hostname is passed to
// a resolution function.
var ErrEmptyHostname = errors.New("empty hostname")

// ErrInvalidB32Length is returned when a .b32.i2p address does not have
// the expected 52-character base32 encoding.
var ErrInvalidB32Length = errors.New("invalid b32 address length")
