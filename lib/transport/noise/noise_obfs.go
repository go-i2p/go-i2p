package noise

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"

	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/common/router_address"
	log "github.com/sirupsen/logrus"
)

// Noise obfuscation functions used in I2P NTCP2 and SSU2 Handshakes,
// including obfuscating the ephemeral keys with a known key and IV found
// in the netDb.

func AESDeObfuscateEphemeralKeys(cipherText string, config noise.Config, bob router_address.RouterAddress) (*noise.DHKey, error) {
	bobsStaticKey, err := bob.StaticKey()
	if err != nil {
		return nil, err
	}
	bobsInitializatonVector, err := bob.InitializationVector()
	if err != nil {
		return nil, err
	}
	log.WithFields(
		log.Fields{
			"at": "(noise) AESObfuscateEphemeralKeys",
		}).Debugf("getting ready to obfuscate our ephemeral keys with bob's static key %s and IV %s", bobsStaticKey, bobsInitializatonVector)
	cipherTextDecoded, err := hex.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(bobsStaticKey[:])
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, bobsInitializatonVector[:])
	mode.CryptBlocks([]byte(cipherTextDecoded), []byte(cipherTextDecoded))
	dhk := &noise.DHKey{
		Private: cipherTextDecoded,
	}
	return dhk, nil
}
