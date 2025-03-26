package elgamal

import "golang.org/x/crypto/openpgp/elgamal"

type elgDecrypter struct {
	k *elgamal.PrivateKey
}

func (elg *elgDecrypter) Decrypt(data []byte) (dec []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Decrypting ElGamal data")
	dec, err = elgamalDecrypt(elg.k, data, true) // TODO(psi): should this be true or false?
	if err != nil {
		log.WithError(err).Error("Failed to decrypt ElGamal data")
	} else {
		log.WithField("decrypted_length", len(dec)).Debug("ElGamal data decrypted successfully")
	}
	return
}
