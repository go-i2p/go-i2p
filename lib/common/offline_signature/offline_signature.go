package offline_signature

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/go-i2p/go-i2p/lib/common/signature"
	"github.com/go-i2p/go-i2p/lib/util/logger"
	"github.com/sirupsen/logrus"
)

const (
	OFFLINE_SIGNATURE_EXPIRY_SIZE  = 4
	OFFLINE_SIGNATURE_SIGTYPE_SIZE = 2
)

var log = logger.GetGoI2PLogger()

/*
[OfflineSignature]
Accurate for version 0.9.63

Description
This is an optional part of the LeaseSet2Header. Also used in streaming and I2CP. Supported as of 0.9.38; see proposal 123 for more information.
Contents

Contains an expiration, a sigtype and transient SigningPublicKey, and a Signature.

+----+----+----+----+----+----+----+----+
|     expires       | sigtype |         |
+----+----+----+----+----+----+         +
|       transient_public_key            |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|           signature                   |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

expires :: 4 byte date
           length -> 4 bytes
           Seconds since the epoch, rolls over in 2106.

sigtype :: 2 byte type of the transient_public_key
           length -> 2 bytes

transient_public_key :: SigningPublicKey
                        length -> As inferred from the sigtype

signature :: Signature
             length -> As inferred from the sigtype of the signing public key
                       in the Destination that preceded this offline signature.
             Signature of expires timestamp, transient sig type, and public key,
             by the destination public key.

https://geti2p.net/spec/common-structures#struct-offlinesignature

*/

// OfflineSignature represents the optional offline signature structure.
type OfflineSignature struct {
	Expires            uint32
	SigType            uint16
	TransientPublicKey []byte
	Signature          []byte
}

// sigTypeKeyLengths returns the public key and signature lengths for a given sigtype.
// Adjust these mappings according to your supported signature types.
func sigTypeKeyLengths(sigtype uint16) (keyLen int, sigLen int, err error) {
	switch sigtype {
	case signature.SIGNATURE_TYPE_DSA_SHA1:
		return 128, 40, nil
	case signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519:
		return 32, 64, nil
	// Add other sigtypes as needed
	default:
		return 0, 0, fmt.Errorf("unsupported sigtype: %d", sigtype)
	}
}

// ReadOfflineSignature parses an OfflineSignature from the given data.
// Returns the parsed OfflineSignature, any remainder data, and an error if parsing fails.
func ReadOfflineSignature(data []byte) (osig OfflineSignature, remainder []byte, err error) {
	if len(data) < 6 { // 4 for expires + 2 for sigtype
		err = errors.New("not enough data to read offline signature header")
		log.WithError(err).Error("Failed to read OfflineSignature: insufficient data for header")
		return
	}

	osig.Expires = binary.BigEndian.Uint32(data[0:4])
	osig.SigType = binary.BigEndian.Uint16(data[4:6])

	keyLen, sigLen, err := sigTypeKeyLengths(osig.SigType)
	if err != nil {
		log.WithError(err).Errorf("Failed to determine key lengths for sigtype %d", osig.SigType)
		return osig, data, err
	}

	needed := 6 + keyLen + sigLen
	if len(data) < needed {
		err = fmt.Errorf("not enough data to read full offline signature (need %d bytes)", needed)
		log.WithError(err).Error("Failed to read OfflineSignature: insufficient data for full structure")
		return osig, data, err
	}

	osig.TransientPublicKey = data[6 : 6+keyLen]
	osig.Signature = data[6+keyLen : 6+keyLen+sigLen]

	remainder = data[6+keyLen+sigLen:]
	log.WithFields(logrus.Fields{
		"expires":              osig.Expires,
		"sigtype":              osig.SigType,
		"transient_key_length": len(osig.TransientPublicKey),
		"signature_length":     len(osig.Signature),
		"remainder_length":     len(remainder),
	}).Debug("Successfully read OfflineSignature")

	return osig, remainder, nil
}

// NewOfflineSignature creates a new OfflineSignature instance.
func NewOfflineSignature(expires uint32, sigType uint16, transientPubKey, signature []byte) (*OfflineSignature, error) {
	keyLen, sigLen, err := sigTypeKeyLengths(sigType)
	if err != nil {
		log.WithError(err).Errorf("Invalid sigtype %d when creating OfflineSignature", sigType)
		return nil, err
	}
	if len(transientPubKey) != keyLen {
		return nil, fmt.Errorf("invalid transient public key length for sigtype %d: expected %d, got %d",
			sigType, keyLen, len(transientPubKey))
	}
	if len(signature) != sigLen {
		return nil, fmt.Errorf("invalid signature length for sigtype %d: expected %d, got %d",
			sigType, sigLen, len(signature))
	}

	osig := &OfflineSignature{
		Expires:            expires,
		SigType:            sigType,
		TransientPublicKey: transientPubKey,
		Signature:          signature,
	}

	log.WithFields(logrus.Fields{
		"expires":              expires,
		"sigtype":              sigType,
		"transient_key_length": len(transientPubKey),
		"signature_length":     len(signature),
	}).Debug("Created new OfflineSignature")

	return osig, nil
}

// Bytes returns the serialized form of the OfflineSignature.
func (osig *OfflineSignature) Bytes() []byte {
	buf := make([]byte, 6+len(osig.TransientPublicKey)+len(osig.Signature))
	binary.BigEndian.PutUint32(buf[0:4], osig.Expires)
	binary.BigEndian.PutUint16(buf[4:6], osig.SigType)
	copy(buf[6:6+len(osig.TransientPublicKey)], osig.TransientPublicKey)
	copy(buf[6+len(osig.TransientPublicKey):], osig.Signature)

	return buf
}

// VerifyOfflineSignature verifies the OfflineSignature given the permanent destination's signing public key.
// The signature is over expires||sigtype||transient_public_key.
func (osig *OfflineSignature) VerifyOfflineSignature(verifyFunc func(data, sig []byte) error) error {
	data := make([]byte, 6+len(osig.TransientPublicKey))
	binary.BigEndian.PutUint32(data[0:4], osig.Expires)
	binary.BigEndian.PutUint16(data[4:6], osig.SigType)
	copy(data[6:], osig.TransientPublicKey)

	err := verifyFunc(data, osig.Signature)
	if err != nil {
		log.WithError(err).Error("OfflineSignature verification failed")
		return err
	}
	log.Debug("OfflineSignature successfully verified")
	return nil
}
