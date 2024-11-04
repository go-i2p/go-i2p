package ntcp

import "github.com/go-i2p/go-i2p/lib/transport/noise"

// Session implements TransportSession
// An established transport session
type Session struct{
	*noise.NoiseSession
}
