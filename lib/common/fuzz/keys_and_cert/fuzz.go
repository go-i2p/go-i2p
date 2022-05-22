package exportable

import common "github.com/go-i2p/go-i2p/lib/common/keys_and_cert"

func Fuzz(data []byte) int {
	keys_and_cert, _, _ := common.ReadKeysAndCert(data)
	keys_and_cert.Certificate()
	keys_and_cert.PublicKey()
	keys_and_cert.SigningPublicKey()
	return 0
}
