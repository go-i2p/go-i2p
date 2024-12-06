package lease_set2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/go-i2p/go-i2p/lib/common/certificate"
	. "github.com/go-i2p/go-i2p/lib/common/data"
	. "github.com/go-i2p/go-i2p/lib/common/destination"
	"github.com/go-i2p/go-i2p/lib/common/lease2"
	. "github.com/go-i2p/go-i2p/lib/common/lease_set2_header"
	"github.com/go-i2p/go-i2p/lib/common/signature"
	"github.com/go-i2p/go-i2p/lib/crypto"
	"github.com/go-i2p/go-i2p/lib/util/logger"
	"github.com/sirupsen/logrus"
)

const (
	LEASE_SET2_NUMK_SIZE           = 1
	LEASE_SET2_KEYTYPE_SIZE        = 2
	LEASE_SET2_KEYLEN_SIZE         = 2
	LEASE_SET2_ENCRYPTION_KEY_SIZE = 256
)

var log = logger.GetGoI2PLogger()

/*
[LeaseSet2]

Description
Contained in a I2NP DatabaseStore message of type 3. Supported as of 0.9.38; see proposal 123 for more information.

Contains all of the currently authorized Lease2 for a particular Destination, and the PublicKey to which garlic messages can be encrypted. A LeaseSet is one of the two structures stored in the network database (the other being RouterInfo), and is keyed under the SHA256 of the contained Destination.
Contents

LeaseSet2Header, followed by a options, then one or more PublicKey for encryption, Integer specifying how many Lease2 structures are in the set, followed by the actual Lease2 structures and finally a Signature of the previous bytes signed by the Destination's SigningPrivateKey or the transient key.

+----+----+----+----+----+----+----+----+
|         ls2_header                    |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|          options                      |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|numk| keytype0| keylen0 |              |
+----+----+----+----+----+              +
|          encryption_key_0             |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| keytypen| keylenn |                   |
+----+----+----+----+                   +
|          encryption_key_n             |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| num| Lease2 0                         |
+----+                                  +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| Lease2($num-1)                        |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| signature                             |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

ls2header :: LeaseSet2Header
             length -> varies

options :: Mapping
           length -> varies, 2 bytes minimum

numk :: Integer
        length -> 1 byte
        Number of key types, key lengths, and PublicKeys to follow
        value: 1 <= numk <= max TBD

keytype :: The encryption type of the PublicKey to follow.
           length -> 2 bytes

keylen :: The length of the PublicKey to follow.
          Must match the specified length of the encryption type.
          length -> 2 bytes

encryption_key :: PublicKey
                  length -> 256 bytes

num :: Integer
       length -> 1 byte
       Number of Lease2s to follow
       value: 0 <= num <= 16

leases :: [Lease2]
          length -> $num*40 bytes

signature :: Signature
             length -> 40 bytes or as specified in destination's key
                       certificate, or by the sigtype of the transient public key,
                       if present in the header

https://geti2p.net/spec/common-structures#leaseset2

*/

// LeaseSet2 is the representation of an I2P LeaseSet2.
type LeaseSet2 []byte

// ParsedLeaseSet2 holds the parsed contents of a LeaseSet2 for easier handling.
type ParsedLeaseSet2 struct {
	Header         ParsedLeaseSet2Header
	Options        Mapping
	EncryptionKeys []EncryptionKeyEntry
	Leases         []lease2.Lease2
	Signature      []byte
	Destination    Destination
	SignatureType  uint16 // from the Destination's or Offline signature
}

// EncryptionKeyEntry holds one encryption key entry.
type EncryptionKeyEntry struct {
	KeyType uint16
	KeyLen  uint16
	KeyData []byte
}

// ReadLeaseSet2 parses a LeaseSet2 from a byte slice.
// Returns a ParsedLeaseSet2 and any remainder after parsing.
func ReadLeaseSet2(data []byte) (parsed ParsedLeaseSet2, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Reading LeaseSet2")

	header, rest, err := ReadLeaseSet2Header(data)
	if err != nil {
		return parsed, data, err
	}
	parsed.Header = header
	parsed.Destination = header.Destination
	remainder = rest

	m, r, errs := NewMapping(remainder)
	if len(errs) != 0 {
		err = WrapErrors(errs)
		log.WithError(err).Error("Failed to parse options")
		return parsed, data, err
	}
	parsed.Options = *m
	remainder = r

	if len(remainder) < 1 {
		err = errors.New("not enough data for numk")
		return parsed, data, err
	}
	numk := int(remainder[0])
	remainder = remainder[1:]

	parsed.EncryptionKeys = make([]EncryptionKeyEntry, 0, numk)
	for i := 0; i < numk; i++ {
		if len(remainder) < 4 {
			err = errors.New("not enough data for keytype/keylen")
			return parsed, data, err
		}
		keytype := binary.BigEndian.Uint16(remainder[0:2])
		keylen := binary.BigEndian.Uint16(remainder[2:4])
		if len(remainder) < 4+int(keylen) {
			err = fmt.Errorf("not enough data for encryption key, need %d bytes", keylen)
			return parsed, data, err
		}
		keydata := remainder[4 : 4+keylen]
		remainder = remainder[4+keylen:]
		parsed.EncryptionKeys = append(parsed.EncryptionKeys, EncryptionKeyEntry{keytype, keylen, keydata})
	}

	if len(remainder) < 1 {
		err = errors.New("not enough data for lease count")
		return parsed, data, err
	}
	num := int(remainder[0])
	remainder = remainder[1:]
	if num > 16 {
		err = fmt.Errorf("invalid lease set2: more than 16 leases (%d)", num)
		return parsed, data, err
	}

	parsed.Leases = make([]lease2.Lease2, 0, num)
	for i := 0; i < num; i++ {
		if len(remainder) < lease2.LEASE2_SIZE {
			err = errors.New("not enough data for Lease2")
			return parsed, data, err
		}
		var l lease2.Lease2
		copy(l[:], remainder[:lease2.LEASE2_SIZE])
		remainder = remainder[lease2.LEASE2_SIZE:]
		parsed.Leases = append(parsed.Leases, l)
	}

	var sigType uint16
	if parsed.Header.OfflineSignature != nil {
		sigType = parsed.Header.OfflineSignature.SigType
	} else {
		ct := parsed.Destination.Certificate()
		t, err2 := certificate.GetSignatureTypeFromCertificate(ct)
		if err2 != nil {
			return parsed, data, err2
		}
		sigType = uint16(t)
	}
	parsed.SignatureType = sigType

	_, sigLen, e := sigTypeKeyLengthsForLS2(sigType)
	if e != nil {
		return parsed, data, e
	}
	if len(remainder) < sigLen {
		err = fmt.Errorf("not enough data for signature, need %d bytes", sigLen)
		return parsed, data, err
	}
	parsed.Signature = remainder[:sigLen]
	remainder = remainder[sigLen:]

	log.WithFields(logrus.Fields{
		"destination_length": len(parsed.Destination.Bytes()),
		"options_count":      len(parsed.Options.Values()),
		"encryption_keys":    len(parsed.EncryptionKeys),
		"lease_count":        len(parsed.Leases),
		"signature_length":   len(parsed.Signature),
		"sigType":            sigType,
	}).Debug("Successfully read LeaseSet2")

	return parsed, remainder, nil
}

// sigTypeKeyLengthsForLS2 returns the signature length for a given sigtype.
// This mirrors the logic in offline_signature or lease_set, but here we only need the signature length.
func sigTypeKeyLengthsForLS2(sigtype uint16) (keyLen int, sigLen int, err error) {
	switch sigtype {
	case signature.SIGNATURE_TYPE_DSA_SHA1:
		return 128, 40, nil
	case signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519:
		return 32, 64, nil
	default:
		return 0, 0, fmt.Errorf("unsupported sigtype: %d", sigtype)
	}
}

// VerifyLeaseSet2 verifies the LeaseSet2 signature.
// `verifyFunc` is a function that verifies data against signature.
func (parsed *ParsedLeaseSet2) VerifyLeaseSet2(verifyFunc func(data, sig []byte) error) error {
	data := parsed.serializeWithoutSignature()
	err := verifyFunc(data, parsed.Signature)
	if err != nil {
		log.WithError(err).Error("LeaseSet2 verification failed")
		return err
	}
	log.Debug("LeaseSet2 successfully verified")
	return nil
}

// serializeWithoutSignature recreates the LeaseSet2 data without the signature.
func (parsed *ParsedLeaseSet2) serializeWithoutSignature() []byte {
	data := parsed.Header.Serialize()

	data = append(data, parsed.Options.Data()...)

	// numk
	data = append(data, byte(len(parsed.EncryptionKeys)))
	for _, ek := range parsed.EncryptionKeys {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint16(buf[0:2], ek.KeyType)
		binary.BigEndian.PutUint16(buf[2:4], ek.KeyLen)
		data = append(data, buf...)
		data = append(data, ek.KeyData...)
	}

	// num
	data = append(data, byte(len(parsed.Leases)))
	for _, l := range parsed.Leases {
		data = append(data, l[:]...)
	}

	return data
}

// Construct a LeaseSet2 from components.
// `sigType` determines the signature size and must be supported by sigTypeKeyLengthsForLS2.
func NewLeaseSet2(
	header ParsedLeaseSet2Header,
	options map[string]string,
	encryptionKeys []EncryptionKeyEntry,
	leases []lease2.Lease2,
	signingPrivateKey crypto.SigningPrivateKey,
	sigType uint16,
) (LeaseSet2, error) {

	if len(leases) > 16 {
		return nil, fmt.Errorf("invalid lease set2: more than 16 leases (%d)", len(leases))
	}

	if len(encryptionKeys) < 1 {
		return nil, errors.New("invalid lease set2: need at least one encryption key")
	}

	mapping, err := GoMapToMapping(options)
	if err != nil {
		return nil, err
	}

	keyLen, _, err := sigTypeKeyLengthsForLS2(sigType)
	if err != nil {
		return nil, err
	}
	_ = keyLen // we don't need keyLen for construction here, just sigLen

	var parsed ParsedLeaseSet2
	parsed.Header = header
	parsed.Options = *mapping
	parsed.EncryptionKeys = encryptionKeys
	parsed.Leases = leases
	parsed.SignatureType = sigType

	data := parsed.serializeWithoutSignature()

	signer, err := signingPrivateKey.NewSigner()
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(data)
	if err != nil {
		return nil, err
	}

	ls2 := append(data, signature...)
	return LeaseSet2(ls2), nil
}
