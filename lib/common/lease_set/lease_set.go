// Package lease_set implements the I2P LeastSet common data structure
package lease_set

import (
	"errors"

	. "github.com/go-i2p/go-i2p/lib/common/certificate"
	. "github.com/go-i2p/go-i2p/lib/common/data"
	. "github.com/go-i2p/go-i2p/lib/common/destination"
	. "github.com/go-i2p/go-i2p/lib/common/key_certificate"
	. "github.com/go-i2p/go-i2p/lib/common/keys_and_cert"
	. "github.com/go-i2p/go-i2p/lib/common/lease"
	. "github.com/go-i2p/go-i2p/lib/common/signature"
	"github.com/go-i2p/go-i2p/lib/crypto"
	log "github.com/sirupsen/logrus"
)

// Sizes of various structures in an I2P LeaseSet
const (
	LEASE_SET_PUBKEY_SIZE = 256
	LEASE_SET_SPK_SIZE    = 128
	LEASE_SET_SIG_SIZE    = 40
)

/*
[LeaseSet]
Accurate for version 0.9.49

Description
Contains all of the currently authorized Leases for a particular Destination, the
PublicKey to which garlic messages can be encrypted, and then the SigningPublicKey
that can be used to revoke this particular version of the structure. The LeaseSet is one
of the two structures stored in the network database (the other being RouterInfo), and
is kered under the SHA256 of the contained Destination.

Contents
Destination, followed by a PublicKey for encryption, then a SigningPublicKey which
can be used to revoke this version of the LeaseSet, then a 1 byte Integer specifying how
many Lease structures are in the set, followed by the actual Lease structures and
finally a Signature of the previous bytes signed by the Destination's SigningPrivateKey.

+----+----+----+----+----+----+----+----+
| destination                           |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| encryption_key                        |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| signing_key                           |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|num | Lease 0                          |
+----+                                  +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| Lease 1                               |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| Lease ($num-1)                        |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| signature                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+

destination :: Destination
               length -> >= 387 bytes

encryption_key :: PublicKey
                  length -> 256 bytes

signing_key :: SigningPublicKey
               length -> 128 bytes or as specified in destination's key certificate

num :: Integer
       length -> 1 byte
       Number of leases to follow
       value: 0 <= num <= 16

leases :: [Lease]
          length -> $num*44 bytes

signature :: Signature
             length -> 40 bytes or as specified in destination's key certificate
*/

// LeaseSet is the represenation of an I2P LeaseSet.
//
// https://geti2p.net/spec/common-structures#leaseset
type LeaseSet []byte

/*
type LeaseSet struct {
	Destination *Destination
	EncryptionKey *crypto.ElgPublicKey
	SigningKey *crypto.ElgPublicKey
	Size *Integer
	Leases []*Lease
	Signature *Signature
}
*/

// Destination returns the Destination as []byte.
func (lease_set LeaseSet) Destination() (destination Destination, err error) {
	keys_and_cert, _, err := NewKeysAndCert(lease_set)
	if err != nil {
		return
	}
	destination, _, err = ReadDestination(keys_and_cert.Bytes())
	return
}

// PublicKey returns the public key as crypto.ElgPublicKey.
// Returns errors encountered during parsing.
func (lease_set LeaseSet) PublicKey() (public_key crypto.ElgPublicKey, err error) {
	_, remainder, err := NewKeysAndCert(lease_set)
	remainder_len := len(remainder)
	if remainder_len < LEASE_SET_PUBKEY_SIZE {
		log.WithFields(log.Fields{
			"at":           "(LeaseSet) PublicKey",
			"data_len":     remainder_len,
			"required_len": LEASE_SET_PUBKEY_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing public key")
		err = errors.New("error parsing public key: not enough data")
		copy(public_key[:], remainder)
		return
	}
	copy(public_key[:], remainder[:LEASE_SET_PUBKEY_SIZE])
	return
}

// SigningKey returns the signing public key as crypto.SigningPublicKey.
// returns errors encountered during parsing.
func (lease_set LeaseSet) SigningKey() (signing_public_key crypto.SigningPublicKey, err error) {
	destination, err := lease_set.Destination()
	if err != nil {
		return
	}
	offset := len(destination.Bytes()) + LEASE_SET_PUBKEY_SIZE
	cert := destination.Certificate()
	cert_len := cert.Length()
	if err != nil {
		return
	}
	lease_set_len := len(lease_set)
	if lease_set_len < offset+LEASE_SET_SPK_SIZE {
		log.WithFields(log.Fields{
			"at":           "(LeaseSet) SigningKey",
			"data_len":     lease_set_len,
			"required_len": offset + LEASE_SET_SPK_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing signing public key")
		err = errors.New("error parsing signing public key: not enough data")
		return
	}
	if cert_len == 0 {
		// No Certificate is present, return the LEASE_SET_SPK_SIZE byte
		// SigningPublicKey space as legacy DSA SHA1 SigningPublicKey.
		var dsa_pk crypto.DSAPublicKey
		copy(dsa_pk[:], lease_set[offset:offset+LEASE_SET_SPK_SIZE])
		signing_public_key = dsa_pk
	} else {
		// A Certificate is present in this LeaseSet's Destination
		cert_type := cert.Type()
		if cert_type == CERT_KEY {
			// This LeaseSet's Destination's Certificate is a Key Certificate,
			// create the signing publickey key using any data that might be
			// contained in the key certificate.
			signing_public_key, err = KeyCertificateFromCertificate(cert).ConstructSigningPublicKey(
				lease_set[offset : offset+LEASE_SET_SPK_SIZE],
			)
		} else {
			// No Certificate is present, return the LEASE_SET_SPK_SIZE byte
			// SigningPublicKey space as legacy DSA SHA1 SigningPublicKey.
			var dsa_pk crypto.DSAPublicKey
			copy(dsa_pk[:], lease_set[offset:offset+LEASE_SET_SPK_SIZE])
			signing_public_key = dsa_pk
		}

	}
	return
}

// LeaseCount returns the numbert of leases specified by the LeaseCount value as int.
// returns errors encountered during parsing.
func (lease_set LeaseSet) LeaseCount() (count int, err error) {
	_, remainder, err := NewKeysAndCert(lease_set)
	if err != nil {
		return
	}
	remainder_len := len(remainder)
	if remainder_len < LEASE_SET_PUBKEY_SIZE+LEASE_SET_SPK_SIZE+1 {
		log.WithFields(log.Fields{
			"at":           "(LeaseSet) LeaseCount",
			"data_len":     remainder_len,
			"required_len": LEASE_SET_PUBKEY_SIZE + LEASE_SET_SPK_SIZE + 1,
			"reason":       "not enough data",
		}).Error("error parsing lease count")
		err = errors.New("error parsing lease count: not enough data")
		return
	}
	c := Integer([]byte{remainder[LEASE_SET_PUBKEY_SIZE+LEASE_SET_SPK_SIZE]})
	count = c.Int()
	if count > 16 {
		log.WithFields(log.Fields{
			"at":          "(LeaseSet) LeaseCount",
			"lease_count": count,
			"reason":      "more than 16 leases",
		}).Warn("invalid lease set")
		err = errors.New("invalid lease set: more than 16 leases")
	}
	return
}

// Leases returns the leases as []Lease.
// returns errors encountered during parsing.
func (lease_set LeaseSet) Leases() (leases []Lease, err error) {
	destination, err := lease_set.Destination()
	if err != nil {
		return
	}
	offset := len(destination.Bytes()) + LEASE_SET_PUBKEY_SIZE + LEASE_SET_SPK_SIZE + 1
	count, err := lease_set.LeaseCount()
	if err != nil {
		return
	}
	for i := 0; i < count; i++ {
		start := offset + (i * LEASE_SIZE)
		end := start + LEASE_SIZE
		lease_set_len := len(lease_set)
		if lease_set_len < end {
			log.WithFields(log.Fields{
				"at":           "(LeaseSet) Leases",
				"data_len":     lease_set_len,
				"required_len": end,
				"reason":       "some leases missing",
			}).Error("error parsnig lease set")
			err = errors.New("error parsing lease set: some leases missing")
			return
		}
		var lease Lease
		copy(lease[:], lease_set[start:end])
		leases = append(leases, lease)
	}
	return
}

// Signature returns the signature as Signature.
// returns errors encountered during parsing.
func (lease_set LeaseSet) Signature() (signature Signature, err error) {
	destination, err := lease_set.Destination()
	if err != nil {
		return
	}
	lease_count, err := lease_set.LeaseCount()
	if err != nil {
		return
	}
	start := len(destination.Bytes()) +
		LEASE_SET_PUBKEY_SIZE +
		LEASE_SET_SPK_SIZE +
		1 +
		(LEASE_SIZE * lease_count)
	cert := destination.Certificate()
	cert_type := cert.Type()
	var end int
	if cert_type == CERT_KEY {
		end = start + KeyCertificateFromCertificate(cert).SignatureSize()
	} else {
		end = start + LEASE_SET_SIG_SIZE
	}
	lease_set_len := len(lease_set)
	if lease_set_len < end {
		log.WithFields(log.Fields{
			"at":           "(LeaseSet) Signature",
			"data_len":     lease_set_len,
			"required_len": end,
			"reason":       "not enough data",
		}).Error("error parsing signatre")
		err = errors.New("error parsing signature: not enough data")
		return
	}
	signature = []byte(lease_set[start:end])
	return
}

// Verify returns nil
func (lease_set LeaseSet) Verify() error {
	//data_end := len(destination) +
	//	LEASE_SET_PUBKEY_SIZE +
	//	LEASE_SET_SPK_SIZE +
	//	1 +
	//	(44 * lease_set.LeaseCount())
	//data := lease_set[:data_end]
	//spk, _ := lease_set.
	//	Destination().
	//	SigningPublicKey()
	//verifier, err := spk.NewVerifier()
	//if err != nil {
	//	return err
	//}
	return nil // verifier.Verify(data, lease_set.Signature())
}

// NewestExpiration returns the newest lease expiration as an I2P Date.
// Returns errors encountered during parsing.
func (lease_set LeaseSet) NewestExpiration() (newest Date, err error) {
	leases, err := lease_set.Leases()
	if err != nil {
		return
	}
	newest = Date{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, lease := range leases {
		date := lease.Date()
		if date.Time().After(newest.Time()) {
			newest = date
		}
	}
	return
}

// OldestExpiration returns the oldest lease expiration as an I2P Date.
// Returns errors encountered during parsing.
func (lease_set LeaseSet) OldestExpiration() (earliest Date, err error) {
	leases, err := lease_set.Leases()
	if err != nil {
		return
	}
	earliest = Date{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for _, lease := range leases {
		date := lease.Date()
		if date.Time().Before(earliest.Time()) {
			earliest = date
		}
	}
	return
}
