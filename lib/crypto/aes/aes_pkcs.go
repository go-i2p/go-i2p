package aes

import (
	"bytes"
	"crypto/aes"

	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

func pkcs7Pad(data []byte, blockSize int) []byte {
	log.WithFields(logrus.Fields{
		"data_length": len(data),
		"block_size":  blockSize,
	}).Debug("Applying PKCS#7 padding")

	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	padded := append(data, padText...)

	log.WithField("padded_length", len(padded)).Debug("PKCS#7 padding applied")
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Removing PKCS#7 padding")

	length := len(data)
	if length == 0 {
		log.Error("Data is empty")
		return nil, oops.Errorf("data is empty")
	}
	padding := int(data[length-1])
	if padding == 0 || padding > aes.BlockSize {
		log.WithField("padding", padding).Error("Invalid padding")
		return nil, oops.Errorf("invalid padding")
	}
	paddingStart := length - padding
	for i := paddingStart; i < length; i++ {
		if data[i] != byte(padding) {
			log.Error("Invalid padding")
			return nil, oops.Errorf("invalid padding")
		}
	}

	unpadded := data[:paddingStart]
	log.WithField("unpadded_length", len(unpadded)).Debug("PKCS#7 padding removed")
	return unpadded, nil
}
