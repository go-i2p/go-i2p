package ntcp

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/common/router_address"

	"github.com/samber/oops"
)

func (t *NTCP2Transport) Address() (*router_address.RouterAddress, error) {
	// Construct a complete NTCP2 address for the transport:
	timeStamp := t.GetCurrentTime().Add(10 * time.Minute)
	// 2. Initialize an empty options map.
	options := make(map[string]string)
	// 3. Create a new RouterAddress with the provided parameters.
	addr, err := router_address.NewRouterAddress(8, timeStamp, t.Name(), options)
	if err != nil {
		return nil, oops.Errorf("failed to create RouterAddress: %w", err)
	}
	// 4. Return the created address or an error if the creation fails.
	return addr, nil
}
