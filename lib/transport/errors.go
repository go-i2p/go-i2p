package transport

import "errors"

// error for when we have no transports available to use
var ErrNoTransportAvailable = errors.New("no transports available")

// ErrConnectionPoolFull is returned when a connection pool has reached its
// maximum capacity and cannot accept new connections.
var ErrConnectionPoolFull = errors.New("connection pool full")
