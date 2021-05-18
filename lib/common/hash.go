package common

import (
	"crypto/sha256"
	"errors"
	log "github.com/sirupsen/logrus"
	"io"
)

const HASH_SIZE = 32

// sha256 hash of some data
type Hash [32]byte

// calculate sha256 of a byte slice
func HashData(data []byte) (h Hash) {
	h = sha256.Sum256(data)
	return
}

// calulate sha256 of all data being read from an io.Reader
// return error if one occurs while reading from reader
func HashReader(r io.Reader) (h Hash, err error) {
	sha := sha256.New()
	_, err = io.Copy(sha, r)
	if err == nil {
		d := sha.Sum(nil)
		copy(h[:], d)
	}
	return
}

func ReadHash(data []byte) (h Hash, remainder []byte, err error) {
	if len(data) < HASH_SIZE {
		log.WithFields(log.Fields{
			"at":           "(Hash) ReadHash",
			"data_len":     len(data),
			"required_len": "32",
			"reason":       "hash missing data",
		}).Error("hash error")
		err = errors.New("error reading hash, insufficient length")
		copy(h[:], data[0:len(data)-1])
	}else{
		copy(h[:], data[0:HASH_SIZE-1])
		copy(remainder, data[HASH_SIZE-1:])
	}
	return
}
