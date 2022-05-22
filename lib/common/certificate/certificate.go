package common

/*
I2P Certificate
https://geti2p.net/spec/common-structures#certificate
Accurate for version 0.9.24

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

// Minimum size of a valid Certificate
const (
	CERT_MIN_SIZE = 3
)

type Certificate struct {
	kind Integer
	leng Integer
	payl []byte
}

func (c *Certificate) RawBytes() []byte {
	bytes := c.kind.Bytes()
	bytes = append(bytes, c.leng.Bytes()...)
	bytes = append(bytes, c.payl...)
	return bytes
}

func (c *Certificate) ExcessBytes() []byte {
	return c.payl[c.leng.Int():]
}

func (c *Certificate) Bytes() []byte {
	bytes := c.kind.Bytes()
	bytes = append(bytes, c.leng.Bytes()...)
	bytes = append(bytes, c.Data()...)
	return bytes
}

func (c *Certificate) length() (cert_len int) {
	cert_len = len(c.Bytes())
	return
}

//
// Return the Certificate Type specified in the first byte of the Certificate,
// and an error if the certificate is shorter than the minimum certificate size.
//
func (c *Certificate) Type() (cert_type int) {
	cert_type = c.kind.Int()
	return
}

//
// Look up the length of the Certificate, reporting errors if the certificate is
// shorter than the minimum certificate size or if the reported length doesn't
// match the provided data.
//
func (c *Certificate) Length() (length int) {
	length = c.leng.Int()
	return
}

//
// Return the Certificate data and any errors encountered parsing the Certificate.
//
func (c *Certificate) Data() (data []byte) {
	lastElement := c.Length()
	if lastElement > len(c.payl) {
		data = c.payl
	} else {
		data = c.payl[0:lastElement]
	}
	return
}

func NewCertificate(data []byte) (certificate *Certificate, err error) {
	certificate = &Certificate{}
	switch len(data) {
	case 0:
		certificate.kind = Integer([]byte{0})
		certificate.leng = Integer([]byte{0})
		log.WithFields(log.Fields{
			"at":                       "(Certificate) NewCertificate",
			"certificate_bytes_length": len(data),
			"reason":                   "too short (len < CERT_MIN_SIZE)" + fmt.Sprintf("%d", certificate.kind.Int()),
		}).Error("invalid certificate")
		err = fmt.Errorf("error parsing certificate: certificate is too short")
		return
	case 1:
		certificate.kind = Integer(data[0:0])
		certificate.leng = Integer([]byte{0})
		log.WithFields(log.Fields{
			"at":                       "(Certificate) NewCertificate",
			"certificate_bytes_length": len(data),
			"reason":                   "too short (len < CERT_MIN_SIZE)" + fmt.Sprintf("%d", certificate.kind.Int()),
		}).Error("invalid certificate")
		err = fmt.Errorf("error parsing certificate: certificate is too short")
		return
	case 2:
		certificate.kind = Integer(data[0:1])
		certificate.leng = Integer([]byte{0})
		log.WithFields(log.Fields{
			"at":                       "(Certificate) NewCertificate",
			"certificate_bytes_length": len(data),
			"reason":                   "too short (len < CERT_MIN_SIZE)" + fmt.Sprintf("%d", certificate.kind.Int()),
		}).Error("invalid certificate")
		err = fmt.Errorf("error parsing certificate length: certificate is too short")
		return
	default:
		certificate.kind = Integer(data[0:1])
		certificate.leng = Integer(data[1:3])
		payleng := len(data) - CERT_MIN_SIZE
		certificate.payl = data[CERT_MIN_SIZE:]
		if certificate.leng.Int() > len(data)-CERT_MIN_SIZE {
			err = fmt.Errorf("certificate parsing warning: certificate data is shorter than specified by length")
			log.WithFields(log.Fields{
				"at":                         "(Certificate) NewCertificate",
				"certificate_bytes_length":   certificate.leng.Int(),
				"certificate_payload_length": payleng,
				"reason":                     err.Error(),
			}).Error("invalid certificate")
			return
		} else if certificate.leng.Int() < len(data)-CERT_MIN_SIZE {
			err = fmt.Errorf("certificate parsing warning: certificate data is longer than specified by length")
			log.WithFields(log.Fields{
				"at":                         "(Certificate) NewCertificate",
				"certificate_bytes_length":   certificate.leng.Int(),
				"certificate_payload_length": payleng,
				"reason":                     err.Error(),
			}).Error("invalid certificate")
			return
		}
		return
	}
}

//
// Read a Certificate from a slice of bytes, returning any extra data on the end of the slice
// and any errors if a valid Certificate could not be read.
//
func ReadCertificate(data []byte) (certificate *Certificate, remainder []byte, err error) {
	certificate, err = NewCertificate(data)
	if err != nil && err.Error() == "certificate parsing warning: certificate data is longer than specified by length" {
		remainder = certificate.ExcessBytes()
		err = nil
	}
	return
}
