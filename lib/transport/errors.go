package transport

import "github.com/samber/oops"

// error for when we have no transports available to use
var ErrNoTransportAvailable = oops.Errorf("no transports available")

// ErrConnectionPoolFull is returned when a connection pool has reached its
// maximum capacity and cannot accept new connections.
var ErrConnectionPoolFull = oops.Errorf("connection pool full")
