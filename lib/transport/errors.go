package transport

import "github.com/samber/oops"

// error for when we have no transports available to use
var ErrNoTransportAvailable = oops.Errorf("no transports available")
