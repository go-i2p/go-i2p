package router

import (
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/netdb"
)

// routerInfoProvider implements netdb.RouterInfoProvider for the Router.
// It provides access to the local router's RouterInfo by constructing it
// from the RouterInfoKeystore.
type routerInfoProvider struct {
	router *Router
}

// GetRouterInfo constructs and returns the current RouterInfo for this router.
// The RouterInfo is built from the router's keystore and includes:
//   - RouterIdentity (encryption/signing keys, certificate)
//   - Published timestamp
//   - Router addresses (e.g., NTCP2 transport addresses)
//   - Options (capabilities, network ID)
//   - Signature
//
// Returns an error if the RouterInfo cannot be constructed.
func (p *routerInfoProvider) GetRouterInfo() (*router_info.RouterInfo, error) {
	// Construct RouterInfo from the keystore
	// nil addresses means it will use default/empty addresses
	// In a full implementation, this would include actual NTCP2/SSU2 addresses
	ri, err := p.router.RouterInfoKeystore.ConstructRouterInfo(nil)
	if err != nil {
		return nil, err
	}

	return ri, nil
}

// newRouterInfoProvider creates a RouterInfoProvider for the given router.
// This is used internally by the Router to provide its RouterInfo to the
// NetDB Publisher for periodic publishing to floodfill routers.
func newRouterInfoProvider(r *Router) netdb.RouterInfoProvider {
	return &routerInfoProvider{
		router: r,
	}
}

// Compile-time interface check
var _ netdb.RouterInfoProvider = (*routerInfoProvider)(nil)
