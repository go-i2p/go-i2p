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
	"errors"
	log "github.com/sirupsen/logrus"
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

type CertificateInterface interface {
	Cert() []byte
	Length() (length int, err error)
	Data() (data []byte, err error)
	Type() (cert_type int, type_bytes []byte, err error)
	SignatureSize() (size int)
}

type Certificate struct {
	CertType  *Integer
	CertLen   *Integer
	CertBytes []byte
}

var ci CertificateInterface = &Certificate{}

func (certificate Certificate) SignatureSize() (size int) {
	return 40
}

func (certificate Certificate) Cert() []byte {
	var ret []byte
	ret = append(ret, certificate.CertType.Bytes()...)
	data, _ := certificate.Data()
	if certificate.CertLen.Value() != 0 && len(data) != 0 {
		ret = append(ret, certificate.CertLen.Bytes()...)
		ret = append(ret, data...)
	} else {
		ret = append(ret, certificate.CertLen.Bytes()...)
	}
	return ret
}

//
// Return the Certificate Type specified in the first byte of the Certificate,
// and an error if the certificate is shorter than the minimum certificate size.
//
func (certificate Certificate) Type() (cert_type int, type_bytes []byte, err error) {
	return certificate.CertType.Value(), certificate.CertType.Bytes(), nil
}

//
// Look up the length of the Certificate, reporting errors if the certificate is
// shorter than the minimum certificate size or if the reported length doesn't
// match the provided data.
//
func (certificate Certificate) Length() (length int, err error) {
	if certificate.CertLen.Value() < 1 {
		log.WithFields(log.Fields{
			"at":                       "(Certificate) Length",
			"certificate_bytes_length": certificate.CertLen,
			"certificate_min_size":     CERT_MIN_SIZE - 1,
			"reason":                   "certificate is too short",
		}).Warn("certificate format warning")
		err = errors.New("error parsing certificate length: certificate is too short")
	}
	if certificate.CertLen.Value() > len(certificate.CertBytes) {
		log.WithFields(log.Fields{
			"at":                        "(Certificate) Length",
			"certificate_bytes_length":  certificate.CertLen,
			"certificate_actual_length": len(certificate.CertBytes),
			"reason":                    "certificate data is shorter than specified by length",
		}).Warn("certificate format warning")
		err = errors.New("certificate parsing warning: certificate data is shorter than specified by length")
		length = len(certificate.CertBytes)
	}
	if certificate.CertLen.Value() < len(certificate.CertBytes) {
		log.WithFields(log.Fields{
			"at":                        "(Certificate) Length",
			"certificate_bytes_length":  certificate.CertLen,
			"certificate_actual_length": len(certificate.CertBytes),
			"reason":                    "certificate contains data beyond length",
		}).Warn("certificate format warning")
		err = errors.New("certificate parsing warning: certificate contains data beyond length")
		length = certificate.CertLen.Value()
		return
	}
	length = certificate.CertLen.Value()
	if err != nil {
		return
	}
	return
}

//
// Return the Certificate data and any errors encountered parsing the Certificate.
//
func (certificate Certificate) Data() (data []byte, err error) {
	_, err = certificate.Length()
	data = certificate.CertBytes
	if err != nil {
		switch err.Error() {
		case "error parsing certificate length: certificate is too short":
			return
		case "certificate parsing warning: certificate data is shorter than specified by length":
			data = certificate.CertBytes
			return
		case "certificate parsing warning: certificate contains data beyond length":
			data = certificate.CertBytes[:certificate.CertLen.Value()]
			return
		}
	}

	return
}

//
// Read a Certificate from a slice of bytes, returning any extra data on the end of the slice
// and any errors if a valid Certificate could not be read.
//
func ReadCertificate(data []byte) (certificate *Certificate, remainder []byte, err error) {
	certificate = &Certificate{}
	certificate.CertType, err = NewInteger(data[0:1])
	certificate.CertLen = &Integer{}
	cert_len := len(data)

	if cert_len < CERT_MIN_SIZE {
		log.WithFields(log.Fields{
			"at":                       "(Certificate) ReadCertificate",
			"certificate_bytes_length": cert_len,
			"certificate_min_size":     CERT_MIN_SIZE,
			"reason":                   "certificate is too short",
		}).Warn("certificate format warning")
		err = errors.New("error parsing certificate length: certificate is too short")
		return
	} else {
		certificate.CertLen, err = NewInteger(data[1:CERT_MIN_SIZE])
		//		_, err = certificate.Type()
		//		if err != nil {
		//			return
		//		}
		certificate.CertBytes = data[CERT_MIN_SIZE:]
		_, err = certificate.Length()
		if err != nil {
			switch err.Error() {
			case "error parsing certificate length: certificate is too short":
				certificate.CertLen, err = NewInteger([]byte{00000000})
				return
			case "certificate parsing warning: certificate data is shorter than specified by length":
				//err = nil
				return
			case "certificate parsing warning: certificate contains data beyond length":
				certificate.CertBytes = data[CERT_MIN_SIZE:]
				remainder = data[CERT_MIN_SIZE+certificate.CertLen.Value():]
				err = nil
				return
			}
		}
	}

	return
}
