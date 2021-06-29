package common

/*
I2P LeaseSet
https://geti2p.net/spec/common-structures#leaseset
Accurate for version 0.9.24

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

import (
	"errors"
	"github.com/go-i2p/go-i2p/lib/crypto"
	log "github.com/sirupsen/logrus"
)

// Sizes of various structures in an I2P LeaseSet
const (
	LEASE_SET_PUBKEY_SIZE = 256
	LEASE_SET_SPK_SIZE    = 128
	LEASE_SET_SIG_SIZE    = 40
)

type LeaseSetInterface interface {
	GetPublicKey() (public_key crypto.ElgPublicKey, err error)
	GetSigningKey() (signing_public_key crypto.SigningPublicKey, err error)
	Leases() (leases []Lease, err error)
	/*	LeaseCount() (count int, err error)*/

	GetSignature() (signature Signature, err error)
	/*	Verify() error
		NewestExpiration() (oldest Date, err error)
		OldestExpiration() (earliest Date, err error)*/
}

type LeaseSet struct {
	Destination
	crypto.SigningPublicKey
	crypto.ElgPublicKey
	LeaseList []Lease
}

var lsi LeaseSetInterface = &LeaseSet{}

//
// Read a Destination from the LeaseSet.
//
func (lease_set LeaseSet) GetDestination() (destination Destination, err error) {
	if &lease_set.Destination != nil {
		destination = lease_set.Destination
	} else {
		err = errors.New("Error leaseset does not contain a destination")
	}
	return
}

//
// Return the PublicKey in this LeaseSet and any errors ancountered parsing the LeaseSet.
//
func (lease_set LeaseSet) GetPublicKey() (public_key crypto.ElgPublicKey, err error) {
	public_key = lease_set.ElgPublicKey
	return
}

//
// Return the SigningPublicKey, as specified in the LeaseSet's Destination's Key Certificate if
// present, or a legacy DSA key.
//
func (lease_set LeaseSet) GetSigningKey() (signing_public_key crypto.SigningPublicKey, err error) {
	if lease_set.SigningPublicKey == nil {
		log.WithFields(log.Fields{
			"at":     "(LeaseSet) SigningKey",
			"public": lease_set.SigningPublicKey,
			"reason": "not enough data",
		}).Error("error parsing signing public key")
		err = errors.New("error parsing signing public key: not enough data")
		return
	}
	signing_public_key = lease_set.SigningPublicKey
	return
}

func (lease_set LeaseSet) Leases() (leases []Lease, err error) {
	leases = lease_set.LeaseList
	return
}

//
// Return the number of Leases specified by the LeaseCount value in this LeaseSet.
//
func (lease_set LeaseSet) LeaseCount() (count int, err error) {
	count = len(lease_set.LeaseList)
	return
}

//
// Return the Signature data for the LeaseSet, as specified in the Destination's
// Key Certificate if present or the 40 bytes following the Leases.
//
func (lease_set LeaseSet) GetSignature() (signature Signature, err error) {
	return
}

//
//
//
/*
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
*/
//
// Return the oldest date from all the Leases in the LeaseSet.
//
func (lease_set LeaseSet) NewestExpiration() (oldest Date, err error) {
	leases, err := lease_set.Leases()
	if err != nil {
		return
	}
	oldest = Date{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, lease := range leases {
		date := lease.Date()
		if date.Time().After(oldest.Time()) {
			oldest = date
		}
	}
	return
}

//
// Return the oldest date from all the Leases in the LeaseSet.
//
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

func ReadLeaseSetSignature(bytes []byte, cert CertificateInterface) (signature Signature, remainder []byte, err error) {
	start := 0
	cert_type, _, _ := cert.Type()
	var end int
	if cert_type == CERT_KEY {
		end = start + cert.SignatureSize()
	} else {
		end = start + LEASE_SET_SIG_SIZE
	}
	bytes_len := len(bytes)
	if bytes_len < end {
		log.WithFields(log.Fields{
			"at":           "(LeaseSet) Signature",
			"data_len":     bytes_len,
			"required_len": end,
			"reason":       "not enough data",
		}).Error("error parsing signatre")
		err = errors.New("error parsing signature: not enough data")
		signature = []byte(bytes[start:bytes_len])
		return
	}
	signature = []byte(bytes[start:end])
	return
}

func ReadLeaseCount(bytes []byte) (count Integer, err error) {
	remainder_len := len(bytes)
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
	count, err = NewInteger([]byte{bytes[LEASE_SET_PUBKEY_SIZE+LEASE_SET_SPK_SIZE]})
	if count.Value() > 16 {
		log.WithFields(log.Fields{
			"at":          "(LeaseSet) LeaseCount",
			"lease_count": count,
			"reason":      "more than 16 leases",
		}).Warn("invalid lease set")
		err = errors.New("invalid lease set: more than 16 leases")
	}
	return
}

//
// Read the Leases in this LeaseSet, returning a partial set if there is insufficient data.
//
func ReadLeases(bytes []byte) (leases []Lease, remainder []byte, err error) {
	count, err := ReadLeaseCount(bytes)
	if err != nil {
		return
	}
	for i := 0; i < count.Value(); i++ {
		start := 0 //offset + (i * LEASE_SIZE)
		end := start + LEASE_SIZE
		lease_set_len := len(bytes)
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
		lease, remainder, err = ReadLease(bytes[start:end])
		leases = append(leases, lease)
		if err != nil {
			return
		}
	}
	return
}

func ReadLeaseSetKeys(data []byte, cert CertificateInterface) (spk crypto.SigningPublicKey, pk crypto.ElgPublicKey, remainder []byte, err error) {
	spk, ppk, remainder, err := ReadKeys(data, cert)
	switch ppk.(type) {
	case crypto.ElgPublicKey:
		pk = ppk.(crypto.ElgPublicKey)
	default:
		err = errors.New("LeaseSet1 uses Elgamal public keys.")
	}
	return
}

func ReadLeaseSet(data []byte) (lease_set LeaseSet, remainder []byte, err error) {
	destination, remainder, err := ReadDestination(data)
	lease_set.Destination = destination
	//offset := len(destination.Bytes()) + LEASE_SET_PUBKEY_SIZE + LEASE_SET_SPK_SIZE + 1
	spk, pk, remainder, err := ReadLeaseSetKeys(remainder, nil)
	lease_set.SigningPublicKey = spk
	lease_set.ElgPublicKey = pk
	leases, remainder, err := ReadLeases(data)
	lease_set.LeaseList = leases

	return
}
