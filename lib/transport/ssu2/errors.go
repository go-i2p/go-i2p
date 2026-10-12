package ssu2

import (
	"github.com/samber/oops"
)

// ErrSSU2NotSupported indicates that a peer/router does not advertise SSU2 support.
var ErrSSU2NotSupported = oops.New("router does not support SSU2")

// ErrSessionClosed is returned when an operation is attempted on a closed SSU2 session.
var ErrSessionClosed = oops.New("SSU2 session is closed")

// ErrDuplicateSession is returned when an inbound connection arrives for a peer
// that already has an active session, so the duplicate is rejected.
var ErrDuplicateSession = oops.New("SSU2 duplicate session from same peer")

// ErrHandshakeFailed is returned when the Noise handshake with a peer fails.
var ErrHandshakeFailed = oops.New("SSU2 handshake failed")

// ErrInvalidRouterInfo is returned when a peer's RouterInfo cannot be used for an SSU2 session.
var ErrInvalidRouterInfo = oops.New("invalid router info for SSU2")

// ErrConnectionPoolFull is returned when the transport has reached its maximum session limit.
var ErrConnectionPoolFull = oops.New("SSU2 connection pool full")

// ErrInvalidListenerAddress is returned when the configured listener address cannot be parsed.
var ErrInvalidListenerAddress = oops.New("invalid listener address for SSU2")

// ErrInvalidConfig is returned when the transport configuration fails validation.
var ErrInvalidConfig = oops.New("invalid SSU2 configuration")

// ErrTransportNotStarted is returned when a NAT detection or relay operation is
// requested before the transport has finished starting up.
var ErrTransportNotStarted = oops.New("SSU2 transport not yet started")

// WrapSSU2Error wraps an error with SSU2 operation context.
// Uses oops.Wrapf which preserves the original error in the chain.
func WrapSSU2Error(err error, operation string) error {
	return oops.Wrapf(err, "SSU2 %s failed", operation)
}
