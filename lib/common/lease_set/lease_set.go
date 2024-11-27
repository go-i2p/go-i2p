// Package lease_set implements the I2P LeastSet common data structure
package lease_set

import (
	"errors"
	"fmt"

	"github.com/go-i2p/go-i2p/lib/common/signature"

	"github.com/go-i2p/go-i2p/lib/util/logger"
	"github.com/sirupsen/logrus"

	. "github.com/go-i2p/go-i2p/lib/common/certificate"
	. "github.com/go-i2p/go-i2p/lib/common/data"
	. "github.com/go-i2p/go-i2p/lib/common/destination"
	. "github.com/go-i2p/go-i2p/lib/common/key_certificate"
	. "github.com/go-i2p/go-i2p/lib/common/keys_and_cert"
	. "github.com/go-i2p/go-i2p/lib/common/lease"
	"github.com/go-i2p/go-i2p/lib/crypto"
)

var log = logger.GetGoI2PLogger()

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
publicKey to which garlic messages can be encrypted, and then the signingPublicKey
that can be used to revoke this particular version of the structure. The LeaseSet is one
of the two structures stored in the network database (the other being RouterInfo), and
is kered under the SHA256 of the contained Destination.

Contents
Destination, followed by a publicKey for encryption, then a signingPublicKey which
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

encryption_key :: publicKey
                  length -> 256 bytes

signing_key :: signingPublicKey
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
	keys_and_cert, _, err := ReadKeysAndCert(lease_set)
	if err != nil {
		log.WithError(err).Error("Failed to read KeysAndCert from LeaseSet")
		return
	}
	destination, _, err = ReadDestination(keys_and_cert.Bytes())
	if err != nil {
		log.WithError(err).Error("Failed to read Destination from KeysAndCert")
	} else {
		log.Debug("Successfully retrieved Destination from LeaseSet")
	}
	return
}

// PublicKey returns the public key as crypto.ElgPublicKey.
// Returns errors encountered during parsing.
func (lease_set LeaseSet) PublicKey() (public_key crypto.ElgPublicKey, err error) {
	_, remainder, err := ReadKeysAndCert(lease_set)
	remainder_len := len(remainder)
	if remainder_len < LEASE_SET_PUBKEY_SIZE {
		log.WithFields(logrus.Fields{
			"at":           "(LeaseSet) publicKey",
			"data_len":     remainder_len,
			"required_len": LEASE_SET_PUBKEY_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing public key")
		err = errors.New("error parsing public key: not enough data")
		copy(public_key[:], remainder)
		return
	}
	copy(public_key[:], remainder[:LEASE_SET_PUBKEY_SIZE])
	log.Debug("Successfully retrieved publicKey from LeaseSet")
	return
}

// SigningKey returns the signing public key as crypto.SigningPublicKey.
// returns errors encountered during parsing.
func (lease_set LeaseSet) SigningKey() (signing_public_key crypto.SigningPublicKey, err error) {
	log.Debug("Retrieving SigningKey from LeaseSet")
	destination, err := lease_set.Destination()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve Destination for SigningKey")
		return
	}
	offset := len(destination.Bytes()) + LEASE_SET_PUBKEY_SIZE
	cert := destination.Certificate()
	cert_len := cert.Length()
	if err != nil {
		log.WithError(err).Error("Failed to get Certificate length")
		return
	}
	lease_set_len := len(lease_set)
	if lease_set_len < offset+LEASE_SET_SPK_SIZE {
		log.WithFields(logrus.Fields{
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
		// signingPublicKey space as legacy DSA SHA1 signingPublicKey.
		var dsa_pk crypto.DSAPublicKey
		copy(dsa_pk[:], lease_set[offset:offset+LEASE_SET_SPK_SIZE])
		signing_public_key = dsa_pk
		log.Debug("Retrieved legacy DSA SHA1 signingPublicKey")
	} else {
		// A Certificate is present in this LeaseSet's Destination
		cert_type := cert.Type()
		if cert_type == CERT_KEY {
			// This LeaseSet's Destination's Certificate is a Key Certificate,
			// create the signing publickey key using any data that might be
			// contained in the key certificate.
			keyCert, err := KeyCertificateFromCertificate(cert)
			if err != nil {
				log.WithError(err).Error("Failed to create keyCert")
			}
			signing_public_key, err = keyCert.ConstructSigningPublicKey(
				lease_set[offset : offset+LEASE_SET_SPK_SIZE],
			)
			if err != nil {
				log.WithError(err).Error("Failed to construct signingPublicKey from keyCertificate")
			} else {
				log.Debug("Retrieved signingPublicKey from keyCertificate")
			}
		} else {
			// No Certificate is present, return the LEASE_SET_SPK_SIZE byte
			// signingPublicKey space as legacy DSA SHA1 signingPublicKey.
			var dsa_pk crypto.DSAPublicKey
			copy(dsa_pk[:], lease_set[offset:offset+LEASE_SET_SPK_SIZE])
			signing_public_key = dsa_pk
			log.Debug("Retrieved legacy DSA SHA1 signingPublicKey (Certificate present but not Key Certificate)")
		}
	}
	return
}

// LeaseCount returns the numbert of leases specified by the LeaseCount value as int.
// returns errors encountered during parsing.
func (lease_set LeaseSet) LeaseCount() (count int, err error) {
	log.Debug("Retrieving LeaseCount from LeaseSet")
	_, remainder, err := ReadKeysAndCert(lease_set)
	if err != nil {
		log.WithError(err).Error("Failed to read KeysAndCert for LeaseCount")
		return
	}
	remainder_len := len(remainder)
	if remainder_len < LEASE_SET_PUBKEY_SIZE+LEASE_SET_SPK_SIZE+1 {
		log.WithFields(logrus.Fields{
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
		log.WithFields(logrus.Fields{
			"at":          "(LeaseSet) LeaseCount",
			"lease_count": count,
			"reason":      "more than 16 leases",
		}).Warn("invalid lease set")
		err = errors.New("invalid lease set: more than 16 leases")
	} else {
		log.WithField("lease_count", count).Debug("Retrieved LeaseCount from LeaseSet")
	}
	return
}

// Leases returns the leases as []Lease.
// returns errors encountered during parsing.
func (lease_set LeaseSet) Leases() (leases []Lease, err error) {
	log.Debug("Retrieving Leases from LeaseSet")
	destination, err := lease_set.Destination()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve Destination for Leases")
		return
	}
	offset := len(destination.Bytes()) + LEASE_SET_PUBKEY_SIZE + LEASE_SET_SPK_SIZE + 1
	count, err := lease_set.LeaseCount()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve LeaseCount for Leases")
		return
	}
	for i := 0; i < count; i++ {
		start := offset + (i * LEASE_SIZE)
		end := start + LEASE_SIZE
		lease_set_len := len(lease_set)
		if lease_set_len < end {
			log.WithFields(logrus.Fields{
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
	log.WithField("lease_count", len(leases)).Debug("Retrieved Leases from LeaseSet")
	return
}

// Signature returns the signature as Signature.
// returns errors encountered during parsing.
func (lease_set LeaseSet) Signature() (signature signature.Signature, err error) {
	log.Debug("Retrieving Signature from LeaseSet")
	destination, err := lease_set.Destination()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve Destination for Signature")
		return
	}
	lease_count, err := lease_set.LeaseCount()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve LeaseCount for Signature")
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
		keyCert, err := KeyCertificateFromCertificate(cert)
		if err != nil {
			log.WithError(err).Error("Failed to create keyCert")
		}
		end = start + keyCert.SignatureSize()
	} else {
		end = start + LEASE_SET_SIG_SIZE
	}
	lease_set_len := len(lease_set)
	if lease_set_len < end {
		log.WithFields(logrus.Fields{
			"at":           "(LeaseSet) Signature",
			"data_len":     lease_set_len,
			"required_len": end,
			"reason":       "not enough data",
		}).Error("error parsing signatre")
		err = errors.New("error parsing signature: not enough data")
		return
	}
	signature = []byte(lease_set[start:end])
	log.WithField("signature_length", len(signature)).Debug("Retrieved Signature from LeaseSet")
	return
}

// Verify returns nil
func (lease_set LeaseSet) Verify() error {
	log.Debug("Verifying LeaseSet")
	//data_end := len(destination) +
	//	LEASE_SET_PUBKEY_SIZE +
	//	LEASE_SET_SPK_SIZE +
	//	1 +
	//	(44 * lease_set.LeaseCount())
	//data := lease_set[:data_end]
	//spk, _ := lease_set.
	//	Destination().
	//	signingPublicKey()
	//verifier, err := spk.NewVerifier()
	//if err != nil {
	//	return err
	//}
	log.Warn("LeaseSet verification not implemented")
	return nil // verifier.Verify(data, lease_set.Signature())
}

// NewestExpiration returns the newest lease expiration as an I2P Date.
// Returns errors encountered during parsing.
func (lease_set LeaseSet) NewestExpiration() (newest Date, err error) {
	log.Debug("Finding newest expiration in LeaseSet")
	leases, err := lease_set.Leases()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve Leases for NewestExpiration")
		return
	}
	newest = Date{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, lease := range leases {
		date := lease.Date()
		if date.Time().After(newest.Time()) {
			newest = date
		}
	}
	log.WithField("newest_expiration", newest.Time()).Debug("Found newest expiration in LeaseSet")
	return
}

// OldestExpiration returns the oldest lease expiration as an I2P Date.
// Returns errors encountered during parsing.
func (lease_set LeaseSet) OldestExpiration() (earliest Date, err error) {
	log.Debug("Finding oldest expiration in LeaseSet")
	leases, err := lease_set.Leases()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve Leases for OldestExpiration")
		return
	}
	earliest = Date{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for _, lease := range leases {
		date := lease.Date()
		if date.Time().Before(earliest.Time()) {
			earliest = date
		}
	}
	log.WithField("oldest_expiration", earliest.Time()).Debug("Found oldest expiration in LeaseSet")
	return
}

func NewLeaseSet(
	destination Destination,
	encryptionKey crypto.PublicKey,
	signingKey crypto.SigningPublicKey,
	leases []Lease,
	signingPrivateKey crypto.SigningPrivateKey,
) (LeaseSet, error) {
	log.Debug("Creating new LeaseSet")
	// Validate destination size
	if len(destination.KeysAndCert.Bytes()) < 387 {
		return nil, errors.New("invalid destination: minimum size is 387 bytes")
	}
	// Validate encryption key size
	if len(encryptionKey.Bytes()) != LEASE_SET_PUBKEY_SIZE {
		return nil, errors.New("invalid encryption key size")
	}
	// Validate inputs
	if len(leases) > 16 {
		return nil, errors.New("invalid lease set: more than 16 leases")
	}
	// Validate signing key size matches certificate
	cert := destination.Certificate()
	if cert.Type() == CERT_KEY {
		// Get expected size from key certificate
		keyCert, err := KeyCertificateFromCertificate(cert)
		if err != nil {
			log.WithError(err).Error("Failed to create keyCert")
		}
		expectedSize := keyCert.SignatureSize()
		if len(signingKey.Bytes()) != expectedSize {
			return nil, fmt.Errorf("invalid signing key size: got %d, expected %d",
				len(signingKey.Bytes()), expectedSize)
		}
	} else {
		// Default DSA size
		if len(signingKey.Bytes()) != LEASE_SET_SPK_SIZE {
			return nil, errors.New("invalid signing key size")
		}
	}
	// Build LeaseSet data
	data := make([]byte, 0)

	// Add Destination
	data = append(data, destination.KeysAndCert.Bytes()...)

	// Add encryption key
	data = append(data, encryptionKey.Bytes()...)

	// Add signing key
	data = append(data, signingKey.Bytes()...)

	// Add lease count
	leaseCount, err := NewIntegerFromInt(len(leases), 1)
	if err != nil {
		log.WithError(err).Error("Failed to create lease count")
		return nil, err
	}
	data = append(data, leaseCount.Bytes()...)

	// Add leases
	for _, lease := range leases {
		data = append(data, lease[:]...)
	}

	// Create signature for all data up to this point
	signer, err := signingPrivateKey.NewSigner()
	if err != nil {
		log.WithError(err).Error("Failed to create signer")
		return nil, err
	}

	signature, err := signer.Sign(data)
	if err != nil {
		log.WithError(err).Error("Failed to sign LeaseSet")
		return nil, err
	}

	// Add signature
	data = append(data, signature...)

	log.WithFields(logrus.Fields{
		"destination_length":    len(destination.KeysAndCert.Bytes()),
		"encryption_key_length": len(encryptionKey.Bytes()),
		"signing_key_length":    len(signingKey.Bytes()),
		"lease_count":           len(leases),
		"total_length":          len(data),
	}).Debug("Successfully created new LeaseSet")

	return LeaseSet(data), nil
}

// NewLeaseSetFromBytes creates a LeaseSet from raw byte data.
func NewLeaseSetFromBytes(data []byte) (LeaseSet, error) {
	log.WithField("data_length", len(data)).Debug("Creating LeaseSet from bytes")

	// Basic size validation
	minSize := LEASE_SET_PUBKEY_SIZE + LEASE_SET_SPK_SIZE + 1 + LEASE_SET_SIG_SIZE
	if len(data) < minSize {
		return nil, errors.New("error parsing lease set: data too short")
	}

	leaseSet := LeaseSet(data)

	// Verify the LeaseSet is valid by trying to read its components
	_, err := leaseSet.Destination()
	if err != nil {
		return nil, err
	}

	_, err = leaseSet.PublicKey()
	if err != nil {
		return nil, err
	}

	_, err = leaseSet.SigningKey()
	if err != nil {
		return nil, err
	}

	count, err := leaseSet.LeaseCount()
	if err != nil {
		return nil, err
	}

	if count > 16 {
		return nil, errors.New("invalid lease set: more than 16 leases")
	}

	_, err = leaseSet.Leases()
	if err != nil {
		return nil, err
	}

	_, err = leaseSet.Signature()
	if err != nil {
		return nil, err
	}

	log.Debug("Successfully created LeaseSet from bytes")
	return leaseSet, nil
}

func NewLeaseSetFromLease(
	destination Destination,
	encryptionKey crypto.PublicKey,
	signingKey crypto.SigningPublicKey,
	lease Lease,
	signingPrivateKey crypto.SigningPrivateKey,
) (LeaseSet, error) {
	log.Debug("Creating LeaseSet from single Lease")

	// Create slice containing just the one lease
	leases := []Lease{lease}

	// Create LeaseSet using the main constructor
	leaseSet, err := NewLeaseSet(
		destination,
		encryptionKey,
		signingKey,
		leases,
		signingPrivateKey,
	)
	if err != nil {
		log.WithError(err).Error("Failed to create LeaseSet from Lease")
		return nil, err
	}

	log.WithFields(logrus.Fields{
		"tunnel_gateway": lease.TunnelGateway(),
		"tunnel_id":      lease.TunnelID(),
		"expiration":     lease.Date().Time(),
	}).Debug("Successfully created LeaseSet from Lease")

	return leaseSet, nil
}
