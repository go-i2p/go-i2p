package ntcp2

import (
	"github.com/samber/oops"
)

var (
	ErrNTCP2NotSupported      = oops.New("router does not support NTCP2")
	ErrSessionClosed          = oops.New("NTCP2 session is closed")
	ErrHandshakeFailed        = oops.New("NTCP2 handshake failed")
	ErrInvalidRouterInfo      = oops.New("invalid router info for NTCP2")
	ErrConnectionPoolFull     = oops.New("NTCP2 connection pool full")
	ErrFramingError           = oops.New("I2NP message framing error")
	ErrInvalidListenerAddress = oops.New("invalid listener address for NTCP2")
)

// Wrap go-noise errors with context
func WrapNTCP2Error(err error, operation string) error {
	return oops.Wrapf(err, "NTCP2 %s failed: %s", operation, err.Error())
}
