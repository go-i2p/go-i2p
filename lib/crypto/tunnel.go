package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

type TunnelData [1028]byte

// A symetric key for encrypting tunnel messages
type TunnelKey [32]byte

// The initialization vector for a tunnel message
type TunnelIV []byte

type Tunnel struct {
	layerKey cipher.Block
	ivKey    cipher.Block
}

func NewTunnelCrypto(layerKey, ivKey TunnelKey) (t *Tunnel, err error) {
	log.Debug("Creating new Tunnel crypto")
	t = new(Tunnel)
	t.layerKey, err = aes.NewCipher(layerKey[:])
	if err == nil {
		t.ivKey, err = aes.NewCipher(ivKey[:])
	}

	if err != nil {
		// error happened we don't need t
		//log.WithError(err).Error("Failed to create Tunnel crypto")
		t = nil
	} else {
		log.Debug("Tunnel crypto created successfully")
	}
	return
}

// encrypt tunnel data in place
func (t *Tunnel) Encrypt(td *TunnelData) {
	log.Debug("Encrypting Tunnel data")
	data := *td
	t.ivKey.Encrypt(data[16:1024], data[16:1024])
	layerBlock := cipher.NewCBCEncrypter(t.layerKey, data[:16])
	layerBlock.CryptBlocks(data[16:1024], data[16:1024])
	t.ivKey.Encrypt(data[16:1024], data[16:1024])
	log.Debug("Tunnel data encrypted successfully")
}

func (t *Tunnel) Decrypt(td *TunnelData) {
	log.Debug("Decrypting Tunnel data")
	data := *td
	t.ivKey.Decrypt(data[16:1024], data[16:1024])
	layerBlock := cipher.NewCBCDecrypter(t.layerKey, data[:16])
	layerBlock.CryptBlocks(data[16:1024], data[16:1024])
	t.ivKey.Decrypt(data[16:1024], data[16:1024])
	log.Debug("Tunnel data decrypted successfully")
}
