package exportable

import common "github.com/go-i2p/go-i2p/lib/common/router_address"

func Fuzz(data []byte) int {
	router_address, _, _ := common.ReadRouterAddress(data)
	router_address.Cost()
	router_address.Expiration()
	router_address.Options()
	router_address.TransportStyle()
	return 0
}
