package transport

import "errors"

// ErrNoTransportAvailable is returned when no transports are available to use.
var ErrNoTransportAvailable = errors.New("no transports available")

// ErrConnectionPoolFull is returned when a connection pool has reached its
// maximum capacity and cannot accept new connections.
var ErrConnectionPoolFull = errors.New("connection pool full")
