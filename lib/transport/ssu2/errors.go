package ssu2

import (
	"github.com/samber/oops"
)

var (
	ErrSSU2NotSupported       = oops.New("router does not support SSU2")
	ErrSessionClosed          = oops.New("SSU2 session is closed")
	ErrHandshakeFailed        = oops.New("SSU2 handshake failed")
	ErrInvalidRouterInfo      = oops.New("invalid router info for SSU2")
	ErrConnectionPoolFull     = oops.New("SSU2 connection pool full")
	ErrInvalidListenerAddress = oops.New("invalid listener address for SSU2")
	ErrInvalidConfig          = oops.New("invalid SSU2 configuration")
)

// WrapSSU2Error wraps an error with SSU2 operation context.
func WrapSSU2Error(err error, operation string) error {
	return oops.Wrapf(err, "SSU2 %s failed", operation)
}
