package exportable

import common "github.com/go-i2p/go-i2p/lib/common/router_identity"

func Fuzz(data []byte) int {
	router_identity, _, _ := common.ReadRouterIdentity(data)
	router_identity.Certificate()
	//router_identity.publicKey()
	//router_identity.signingPublicKey()
	return 0
}
