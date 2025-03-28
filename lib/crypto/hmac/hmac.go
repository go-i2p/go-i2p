package hmac

import (
	"crypto/hmac"
	"crypto/md5"
)

type (
	HMACKey    [32]byte
	HMACDigest [16]byte
)

// I2PHMAC computes HMAC-MD5 using the provided key and data
func I2PHMAC(data []byte, k HMACKey) (d HMACDigest) {
	// Create a new HMAC instance using MD5 hash and our key
	mac := hmac.New(md5.New, k[:])

	// Write data to HMAC
	mac.Write(data)

	// Calculate the HMAC and extract the digest
	digest := mac.Sum(nil)

	// Copy to our fixed-size return type
	copy(d[:], digest)
	return
}
