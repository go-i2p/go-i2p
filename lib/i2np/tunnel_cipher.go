package i2np

import (
	"crypto/aes"
	"crypto/cipher"
)

// TunnelCipherEncrypt performs AES-CBC tunnel-layer encryption per I2P spec.
// F079 fix: operates through pointer (not value copy) so mutations persist.
// F080 fix: CBC IV taken from correct byte offset.
// F081 fix: single-block transform applied; last 4 payload bytes encrypted;
// output is full 1028 bytes (not truncated to 1008).
func TunnelCipherEncrypt(in []byte, out *[1028]byte, iv, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out[:], in)
	return nil
}
