package ntcp2

import (
	"github.com/samber/oops"
)

// ErrNTCP2NotSupported indicates that a peer/router does not advertise NTCP2 support.
var ErrNTCP2NotSupported = oops.New("router does not support NTCP2")

// ErrSessionClosed is returned when an operation is attempted on a closed NTCP2 session.
var ErrSessionClosed = oops.New("NTCP2 session is closed")

// ErrHandshakeFailed is returned when the Noise XK handshake with a peer fails.
var ErrHandshakeFailed = oops.New("NTCP2 handshake failed")

// ErrInvalidRouterInfo is returned when a peer's RouterInfo cannot be used for an NTCP2 session.
var ErrInvalidRouterInfo = oops.New("invalid router info for NTCP2")

// ErrConnectionPoolFull is returned when the transport has reached its maximum session limit.
var ErrConnectionPoolFull = oops.New("NTCP2 connection pool full")

// ErrFramingError is returned when an I2NP message cannot be framed or unframed correctly.
var ErrFramingError = oops.New("I2NP message framing error")

// ErrInvalidListenerAddress is returned when the configured listener address cannot be parsed.
var ErrInvalidListenerAddress = oops.New("invalid listener address for NTCP2")

// ErrInvalidConfig is returned when the transport configuration fails validation.
var ErrInvalidConfig = oops.New("invalid NTCP2 configuration")

// ErrUnexpectedConnType is returned when an accepted connection is not the expected NTCP2 connection type.
var ErrUnexpectedConnType = oops.New("accepted connection is not *ntcp2.Conn")

// WrapNTCP2Error wraps an error with NTCP2 operation context.
// Uses oops.Wrapf which preserves the original error in the chain.
func WrapNTCP2Error(err error, operation string) error {
	return oops.Wrapf(err, "NTCP2 %s failed", operation)
}
