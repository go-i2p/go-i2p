// Package certificate implements the certificate common-structure of I2P.

package certificate

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	. "github.com/go-i2p/go-i2p/lib/common/data"
)

// Certificate Types
const (
	CERT_NULL = iota
	CERT_HASHCASH
	CERT_HIDDEN
	CERT_SIGNED
	CERT_MULTIPLE
	CERT_KEY
)

// CERT_MIN_SIZE is the minimum size of a valid Certificate in []byte
// 1 byte for type
// 2 bytes for payload length
const CERT_MIN_SIZE = 3

/*
[I2P Certificate]
Accurate for version 0.9.49

Description
A certifificate is a container for various receipts of proof of works used throughout the I2P network.

Contents
1 byte Integer specifying certificate type, followed by a 2 byte Integer specifying the size of the certificate playload, then that many bytes.

+----+----+----+----+----+-//
|type| length  | payload
+----+----+----+----+----+-//

type :: Integer
        length -> 1 byte

        case 0 -> NULL
        case 1 -> HASHCASH
        case 2 -> HIDDEN
        case 3 -> SIGNED
        case 4 -> MULTIPLE
        case 5 -> KEY

length :: Integer
          length -> 2 bytes

payload :: data
           length -> $length bytes
*/

// Certificate is the representation of an I2P Certificate.
//
// https://geti2p.net/spec/common-structures#certificate
type Certificate struct {
	kind    Integer
	len     Integer
	payload []byte
}

// RawBytes returns the entire certificate in []byte form, includes excess payload data.
func (c *Certificate) RawBytes() []byte {
	bytes := c.kind.Bytes()
	bytes = append(bytes, c.len.Bytes()...)
	bytes = append(bytes, c.payload...)
	return bytes
}

// ExcessBytes returns the excess bytes in a certificate found after the specified payload length.
func (c *Certificate) ExcessBytes() []byte {
	log.Println("Bytes after:", c.len.Int())
	return c.payload[c.len.Int():]
}

// Bytes returns the entire certificate in []byte form, trims payload to specified length.
func (c *Certificate) Bytes() []byte {
	bytes := c.kind.Bytes()
	bytes = append(bytes, c.len.Bytes()...)
	bytes = append(bytes, c.Data()...)
	return bytes
}

func (c *Certificate) length() (cert_len int) {
	cert_len = len(c.Bytes())
	return
}

// Type returns the Certificate type specified in the first byte of the Certificate,
func (c *Certificate) Type() (cert_type int) {
	cert_type = c.kind.Int()
	return
}

// Length returns the payload length of a Certificate.
func (c *Certificate) Length() (length int) {
	length = c.len.Int()
	return
}

// Data returns the payload of a Certificate, payload is trimmed to the specified length.
func (c *Certificate) Data() (data []byte) {
	lastElement := c.Length()
	if lastElement > len(c.payload) {
		data = c.payload
	} else {
		data = c.payload[0:lastElement]
	}
	return
}

// NewCertificate creates a new Certficiate from []byte
// returns err if the certificate is too short or if the payload doesn't match specified length.
func NewCertificate(data []byte) (certificate *Certificate, err error) {
	certificate = &Certificate{}
	switch len(data) {
	case 0:
		certificate.kind = Integer([]byte{0})
		certificate.len = Integer([]byte{0})
		log.WithFields(log.Fields{
			"at":                       "(Certificate) NewCertificate",
			"certificate_bytes_length": len(data),
			"reason":                   "too short (len < CERT_MIN_SIZE)" + fmt.Sprintf("%d", certificate.kind.Int()),
		}).Error("invalid certificate, empty")
		err = fmt.Errorf("error parsing certificate: certificate is empty")
		return
	case 1 , 2:
		certificate.kind = Integer(data[0:len(data)-1])
		certificate.len = Integer([]byte{0})
		log.WithFields(log.Fields{
			"at":                       "(Certificate) NewCertificate",
			"certificate_bytes_length": len(data),
			"reason":                   "too short (len < CERT_MIN_SIZE)" + fmt.Sprintf("%d", certificate.kind.Int()),
		}).Error("invalid certificate, too short")
		err = fmt.Errorf("error parsing certificate: certificate is too short")
		return
	default:
		certificate.kind = Integer(data[0:1])
		certificate.len = Integer(data[1:3])
		payleng := len(data) - CERT_MIN_SIZE
		certificate.payload = data[CERT_MIN_SIZE:]
		if certificate.len.Int() > len(data)-CERT_MIN_SIZE {
			err = fmt.Errorf("certificate parsing warning: certificate data is shorter than specified by length")
			log.WithFields(log.Fields{
				"at":                         "(Certificate) NewCertificate",
				"certificate_bytes_length":   certificate.len.Int(),
				"certificate_payload_length": payleng,
				"data_bytes:":                string(data),
				"kind_bytes":                 data[0:1],
				"len_bytes":                  data[1:3],
				"reason":                     err.Error(),
			}).Error("invalid certificate, shorter than specified by length")
			return
		} else if certificate.len.Int() < len(data)-CERT_MIN_SIZE {
			err = fmt.Errorf("certificate parsing warning: certificate data is longer than specified by length")
			log.WithFields(log.Fields{
				"at":                         "(Certificate) NewCertificate",
				"certificate_bytes_length":   certificate.len.Int(),
				"certificate_payload_length": payleng,
				"data_bytes:":                string(data),
				"kind_bytes":                 data[0:1],
				"len_bytes":                  data[1:3],
				"reason":                     err.Error(),
			}).Error("invalid certificate, longer than specified by length")
			return
		}
		return
	}
}

// ReadCertificate creates a Certificate from []byte and returns any ExcessBytes at the end of the input.
// returns err if the certificate could not be read.
func ReadCertificate(data []byte) (certificate *Certificate, remainder []byte, err error) {
	certificate, err = NewCertificate(data)
	if err != nil && err.Error() == "certificate parsing warning: certificate data is longer than specified by length" {
		err = nil
	}
	remainder = certificate.ExcessBytes()
	return
}
