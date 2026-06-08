package ssu2

import (
	"github.com/samber/oops"
)

var (
	// ErrSSU2NotSupported indicates that a peer/router does not advertise SSU2 support.
	ErrSSU2NotSupported       = oops.New("router does not support SSU2")
	ErrSessionClosed          = oops.New("SSU2 session is closed")
	ErrDuplicateSession       = oops.New("SSU2 duplicate session from same peer")
	ErrHandshakeFailed        = oops.New("SSU2 handshake failed")
	ErrInvalidRouterInfo      = oops.New("invalid router info for SSU2")
	ErrConnectionPoolFull     = oops.New("SSU2 connection pool full")
	ErrInvalidListenerAddress = oops.New("invalid listener address for SSU2")
	ErrInvalidConfig          = oops.New("invalid SSU2 configuration")
	ErrTransportNotStarted    = oops.New("SSU2 transport not yet started")
)

// WrapSSU2Error wraps an error with SSU2 operation context.
func WrapSSU2Error(err error, operation string) error {
	return oops.Wrapf(err, "SSU2 %s failed", operation)
}
