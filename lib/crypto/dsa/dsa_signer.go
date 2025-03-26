package dsa

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha1"
	"math/big"
)

type DSASigner struct {
	k *dsa.PrivateKey
}

func (ds *DSASigner) Sign(data []byte) (sig []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Signing data with DSA")
	h := sha1.Sum(data)
	sig, err = ds.SignHash(h[:])
	return
}

func (ds *DSASigner) SignHash(h []byte) (sig []byte, err error) {
	log.WithField("hash_length", len(h)).Debug("Signing hash with DSA")
	var r, s *big.Int
	r, s, err = dsa.Sign(rand.Reader, ds.k, h)
	if err == nil {
		sig = make([]byte, 40)
		rb := r.Bytes()
		rl := len(rb)
		copy(sig[20-rl:20], rb)
		sb := s.Bytes()
		sl := len(sb)
		copy(sig[20+(20-sl):], sb)
		log.WithField("sig_length", len(sig)).Debug("DSA signature created successfully")
	} else {
		log.WithError(err).Error("Failed to create DSA signature")
	}
	return
}
