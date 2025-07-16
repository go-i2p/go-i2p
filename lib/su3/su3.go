// Package su3 implements reading the SU3 file format.
//
// SU3 files provide content that is signed by a known identity.
// They are used to distribute many types of data, including reseed files,
// plugins, blocklists, and more.
//
// See: https://geti2p.net/spec/updates#su3-file-specification
//
// The Read() function takes an io.Reader, and it returns a *SU3. The *SU3 contains
// the SU3 file metadata, such as the type of the content and the signer ID.
// In order to get the file contents, one must pass in the public key associated
// with the file's signer, so that the signature can be validated. The content
// can still be read without passing in the key, but after returning the full
// content the error ErrInvalidSignature will be returned.
//
// Example usage:
//
//	    // Let's say we are reading an SU3 file from an HTTP body, which is an io.Reader.
//	    su3File, err := su3.Read(body)
//	    if err != nil {
//	        // Handle error.
//	    }
//	    // Look up this signer's key.
//	    key := somehow_lookup_the_key(su3File.SignerID)
//	    // Read the content.
//	    contentReader := su3File.Content(key)
//	    bytes, err := ioutil.ReadAll(contentReader)
//	    if errors.Is(err, su3.ErrInvalidSignature) {
//		       // The signature is invalid, OR a nil key was provided.
//	    } else if err != nil {
//	        // Handle error.
//	    }
//
// If you want to parse from a []byte, you can wrap it like this:
//
//	mySU3FileBytes := []byte{0x00, 0x01, 0x02, 0x03}
//	su3File, err := su3.Read(bytes.NewReader(mySU3FileBytes))
//
// One of the advantages of this library's design is that you can avoid buffering
// the file contents in memory. Here's how you would stream from an HTTP body
// directly to disk:
//
//	    su3File, err := su3.Read(body)
//	    if err != nil {
//		       // Handle error.
//	    }
//	    // Look up this signer's key.
//	    key := somehow_lookup_the_key(su3File.SignerID)
//	    // Stream directly to disk.
//	    f, err := os.Create("my_file.txt")
//	    if err != nil {
//		       // Handle error.
//	    }
//	    _, err := io.Copy(f, su3File.Content(key))
//	    if errors.Is(err, su3.ErrInvalidSignature) {
//		       // The signature is invalid, OR a nil key was provided.
//	        // Don't trust the file, delete it!
//	    } else if err != nil {
//	        // Handle error.
//	    }
//
// Note: if you want to read the content, the Content() io.Reader must be read
// *before* the Signature() io.Reader. If you read the signature first, the
// content bytes will be thrown away. If you then attempt to read the content,
// you will get an error. For clarification, see TestReadSignatureFirst.
package su3

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

var log = logger.GetGoI2PLogger()

type SignatureType string

const (
	DSA_SHA1               SignatureType = "DSA-SHA1"
	ECDSA_SHA256_P256      SignatureType = "ECDSA-SHA256-P256"
	ECDSA_SHA384_P384      SignatureType = "ECDSA-SHA384-P384"
	ECDSA_SHA512_P521      SignatureType = "ECDSA-SHA512-P521"
	RSA_SHA256_2048        SignatureType = "RSA-SHA256-2048"
	RSA_SHA384_3072        SignatureType = "RSA-SHA384-3072"
	RSA_SHA512_4096        SignatureType = "RSA-SHA512-4096"
	EdDSA_SHA512_Ed25519ph SignatureType = "EdDSA-SHA512-Ed25519ph"
)

var sigTypes = map[[2]byte]SignatureType{
	{0x00, 0x00}: DSA_SHA1,
	{0x00, 0x01}: ECDSA_SHA256_P256,
	{0x00, 0x02}: ECDSA_SHA384_P384,
	{0x00, 0x03}: ECDSA_SHA512_P521,
	{0x00, 0x04}: RSA_SHA256_2048,
	{0x00, 0x05}: RSA_SHA384_3072,
	{0x00, 0x06}: RSA_SHA512_4096,
	{0x00, 0x08}: EdDSA_SHA512_Ed25519ph,
}

type FileType string

const (
	ZIP      FileType = "zip"
	XML      FileType = "xml"
	HTML     FileType = "html"
	XML_GZIP FileType = "xml.gz"
	TXT_GZIP FileType = "txt.gz"
	DMG      FileType = "dmg"
	EXE      FileType = "exe"
)

var fileTypes = map[byte]FileType{
	0x00: ZIP,
	0x01: XML,
	0x02: HTML,
	0x03: XML_GZIP,
	0x04: TXT_GZIP,
	0x05: DMG,
	0x06: EXE,
}

type ContentType string

const (
	UNKNOWN       ContentType = "unknown"
	ROUTER_UPDATE ContentType = "router_update"
	PLUGIN        ContentType = "plugin"
	RESEED        ContentType = "reseed"
	NEWS          ContentType = "news"
	BLOCKLIST     ContentType = "blocklist"
)

var contentTypes = map[byte]ContentType{
	0x00: UNKNOWN,
	0x01: ROUTER_UPDATE,
	0x02: PLUGIN,
	0x03: RESEED,
	0x04: NEWS,
	0x05: BLOCKLIST,
}

var (
	ErrMissingMagicBytes        = oops.Errorf("missing magic bytes")
	ErrMissingUnusedByte6       = oops.Errorf("missing unused byte 6")
	ErrMissingFileFormatVersion = oops.Errorf("missing or incorrect file format version")
	ErrMissingSignatureType     = oops.Errorf("missing or invalid signature type")
	ErrUnsupportedSignatureType = oops.Errorf("unsupported signature type")
	ErrMissingSignatureLength   = oops.Errorf("missing signature length")
	ErrMissingUnusedByte12      = oops.Errorf("missing unused byte 12")
	ErrMissingVersionLength     = oops.Errorf("missing version length")
	ErrVersionTooShort          = oops.Errorf("version length too short")
	ErrMissingUnusedByte14      = oops.Errorf("missing unused byte 14")
	ErrMissingSignerIDLength    = oops.Errorf("missing signer ID length")
	ErrMissingContentLength     = oops.Errorf("missing content length")
	ErrMissingUnusedByte24      = oops.Errorf("missing unused byte 24")
	ErrMissingFileType          = oops.Errorf("missing or invalid file type")
	ErrMissingUnusedByte26      = oops.Errorf("missing unused byte 26")
	ErrMissingContentType       = oops.Errorf("missing or invalid content type")
	ErrMissingUnusedBytes28To39 = oops.Errorf("missing unused bytes 28-39")
	ErrMissingVersion           = oops.Errorf("missing version")
	ErrMissingSignerID          = oops.Errorf("missing signer ID")
	ErrMissingContent           = oops.Errorf("missing content")
	ErrMissingSignature         = oops.Errorf("missing signature")
	ErrInvalidPublicKey         = oops.Errorf("invalid public key")
	ErrInvalidSignature         = oops.Errorf("invalid signature")
)

const magicBytes = "I2Psu3"

type SU3 struct {
	SignatureType   SignatureType
	SignatureLength uint16
	ContentLength   uint64
	FileType        FileType
	ContentType     ContentType
	Version         string
	SignerID        string
	mut             sync.Mutex
	reader          io.Reader
	publicKey       interface{}
	contentReader   *contentReader
	signatureReader *signatureReader
}

func (su3 *SU3) Content(publicKey interface{}) io.Reader {
	log.WithField("signer_id", su3.SignerID).Debug("Accessing SU3 content")
	su3.publicKey = publicKey
	return su3.contentReader
}

func (su3 *SU3) Signature() io.Reader {
	log.Debug("Accessing SU3 signature")
	return su3.signatureReader
}

func Read(reader io.Reader) (su3 *SU3, err error) {
	log.Debug("Starting to read SU3 file")
	var buff bytes.Buffer

	if err := readAndValidateMagicBytes(reader, &buff); err != nil {
		return nil, err
	}

	if err := readFileFormatHeader(reader, &buff); err != nil {
		return nil, err
	}

	su3 = &SU3{
		mut:    sync.Mutex{},
		reader: reader,
	}

	sigType, err := readSignatureInfo(reader, su3, &buff)
	if err != nil {
		return nil, err
	}

	verLen, signIDLen, err := readLengthFields(reader, su3, &buff)
	if err != nil {
		return nil, err
	}

	if err := readFileMetadata(reader, su3, &buff); err != nil {
		return nil, err
	}

	if err := readUnusedBytes28To39(reader, &buff); err != nil {
		return nil, err
	}

	if err := readVersionAndSignerID(reader, su3, &buff, verLen, signIDLen); err != nil {
		return nil, err
	}

	if err := initializeReaders(su3, sigType, &buff); err != nil {
		return nil, err
	}

	log.WithFields(logrus.Fields{
		"signature_type": su3.SignatureType,
		"file_type":      su3.FileType,
		"content_type":   su3.ContentType,
		"version":        su3.Version,
		"signer_id":      su3.SignerID,
	}).Debug("SU3 file read successfully")

	return su3, nil
}

// readAndValidateMagicBytes reads and validates the SU3 file magic bytes.
func readAndValidateMagicBytes(reader io.Reader, buff *bytes.Buffer) error {
	mbytes := make([]byte, len(magicBytes))
	l, err := reader.Read(mbytes)
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read magic bytes")
		return oops.Errorf("reading magic bytes: %w", err)
	}
	if l != len(mbytes) {
		log.Error("Missing magic bytes")
		return ErrMissingMagicBytes
	}
	if string(mbytes) != magicBytes {
		log.Error("Invalid magic bytes")
		return ErrMissingMagicBytes
	}
	buff.Write(mbytes)
	log.Debug("Magic bytes verified")
	return nil
}

// readFileFormatHeader reads the unused byte 6 and file format version.
func readFileFormatHeader(reader io.Reader, buff *bytes.Buffer) error {
	unused := [1]byte{}

	// Unused byte 6.
	l, err := reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read unused byte 6")
		return oops.Errorf("reading unused byte 6: %w", err)
	}
	if l != 1 {
		log.Error("Missing unused byte 6")
		return ErrMissingUnusedByte6
	}
	buff.Write(unused[:])
	log.Debug("Read unused byte 6")

	// SU3 file format version (always 0).
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read SU3 file format version")
		return oops.Errorf("reading SU3 file format version: %w", err)
	}
	if l != 1 {
		log.Error("Missing SU3 file format version")
		return ErrMissingFileFormatVersion
	}
	if unused[0] != 0x00 {
		log.Error("Invalid SU3 file format version")
		return ErrMissingFileFormatVersion
	}
	buff.Write(unused[:])
	log.Debug("SU3 file format version verified")

	return nil
}

// readSignatureInfo reads signature type and length, returning the signature type.
func readSignatureInfo(reader io.Reader, su3 *SU3, buff *bytes.Buffer) (SignatureType, error) {
	// Signature type.
	sigTypeBytes := [2]byte{}
	l, err := reader.Read(sigTypeBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read signature type")
		return "", oops.Errorf("reading signature type: %w", err)
	}
	if l != 2 {
		log.Error("Missing signature type")
		return "", ErrMissingSignatureType
	}
	sigType, ok := sigTypes[sigTypeBytes]
	if !ok {
		log.WithField("signature_type", sigTypeBytes).Error("Unsupported signature type")
		return "", ErrUnsupportedSignatureType
	}
	su3.SignatureType = sigType
	buff.Write(sigTypeBytes[:])
	log.WithField("signature_type", sigType).Debug("Signature type read")

	// Signature length.
	sigLengthBytes := [2]byte{}
	l, err = reader.Read(sigLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read signature length")
		return "", oops.Errorf("reading signature length: %w", err)
	}
	if l != 2 {
		log.Error("Missing signature length")
		return "", ErrMissingSignatureLength
	}
	sigLen := binary.BigEndian.Uint16(sigLengthBytes[:])
	// TODO check that sigLen is the correct length for sigType.
	su3.SignatureLength = sigLen
	buff.Write(sigLengthBytes[:])
	log.WithField("signature_length", sigLen).Debug("Signature length read")

	return sigType, nil
}

// readLengthFields reads various length fields including version and signer ID lengths.
func readLengthFields(reader io.Reader, su3 *SU3, buff *bytes.Buffer) (uint16, uint16, error) {
	unused := [1]byte{}

	// Unused byte 12.
	l, err := reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read unused byte 12")
		return 0, 0, oops.Errorf("reading unused byte 12: %w", err)
	}
	if l != 1 {
		log.Error("Missing unused byte 12")
		return 0, 0, ErrMissingUnusedByte12
	}
	buff.Write(unused[:])
	log.Debug("Read unused byte 12")

	// Version length.
	verLengthBytes := [1]byte{}
	l, err = reader.Read(verLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read version length")
		return 0, 0, oops.Errorf("reading version length: %w", err)
	}
	if l != 1 {
		log.Error("Missing version length")
		return 0, 0, ErrMissingVersionLength
	}
	verLen := binary.BigEndian.Uint16([]byte{0x00, verLengthBytes[0]})
	if verLen < 16 {
		log.WithField("version_length", verLen).Error("Version length too short")
		return 0, 0, ErrVersionTooShort
	}
	buff.Write(verLengthBytes[:])
	log.WithField("version_length", verLen).Debug("Version length read")

	// Unused byte 14.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read unused byte 14")
		return 0, 0, oops.Errorf("reading unused byte 14: %w", err)
	}
	if l != 1 {
		log.Error("Missing unused byte 14")
		return 0, 0, ErrMissingUnusedByte14
	}
	buff.Write(unused[:])
	log.Debug("Read unused byte 14")

	// Signer ID length.
	sigIDLengthBytes := [1]byte{}
	l, err = reader.Read(sigIDLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read signer ID length")
		return 0, 0, oops.Errorf("reading signer id length: %w", err)
	}
	if l != 1 {
		log.Error("Missing signer ID length")
		return 0, 0, ErrMissingSignerIDLength
	}
	signIDLen := binary.BigEndian.Uint16([]byte{0x00, sigIDLengthBytes[0]})
	buff.Write(sigIDLengthBytes[:])
	log.WithField("signer_id_length", signIDLen).Debug("Signer ID length read")

	return verLen, signIDLen, nil
}

// readFileMetadata reads content length, file type, and content type.
func readFileMetadata(reader io.Reader, su3 *SU3, buff *bytes.Buffer) error {
	unused := [1]byte{}

	// Content length.
	contentLengthBytes := [8]byte{}
	l, err := reader.Read(contentLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read content length")
		return oops.Errorf("reading content length: %w", err)
	}
	if l != 8 {
		log.Error("Missing content length")
		return ErrMissingContentLength
	}
	contentLen := binary.BigEndian.Uint64(contentLengthBytes[:])
	su3.ContentLength = contentLen
	buff.Write(contentLengthBytes[:])
	log.WithField("content_length", contentLen).Debug("Content length read")

	// Unused byte 24.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read unused byte 24")
		return oops.Errorf("reading unused byte 24: %w", err)
	}
	if l != 1 {
		log.Error("Missing unused byte 24")
		return ErrMissingUnusedByte24
	}
	buff.Write(unused[:])
	log.Debug("Read unused byte 24")

	// File type.
	fileTypeBytes := [1]byte{}
	l, err = reader.Read(fileTypeBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read file type")
		return oops.Errorf("reading file type: %w", err)
	}
	if l != 1 {
		log.Error("Missing file type")
		return ErrMissingFileType
	}
	fileType, ok := fileTypes[fileTypeBytes[0]]
	if !ok {
		log.WithField("file_type_byte", fileTypeBytes[0]).Error("Invalid file type")
		return ErrMissingFileType
	}
	su3.FileType = fileType
	buff.Write(fileTypeBytes[:])
	log.WithField("file_type", fileType).Debug("File type read")

	// Unused byte 26.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read unused byte 26")
		return oops.Errorf("reading unused byte 26: %w", err)
	}
	if l != 1 {
		log.Error("Missing unused byte 26")
		return ErrMissingUnusedByte26
	}
	buff.Write(unused[:])
	log.Debug("Read unused byte 26")

	// Content type.
	contentTypeBytes := [1]byte{}
	l, err = reader.Read(contentTypeBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read content type")
		return oops.Errorf("reading content type: %w", err)
	}
	if l != 1 {
		log.Error("Missing content type")
		return ErrMissingContentType
	}
	contentType, ok := contentTypes[contentTypeBytes[0]]
	if !ok {
		log.WithField("content_type_byte", contentTypeBytes[0]).Error("Invalid content type")
		return ErrMissingContentType
	}
	su3.ContentType = contentType
	buff.Write(contentTypeBytes[:])
	log.WithField("content_type", contentType).Debug("Content type read")

	return nil
}

// readUnusedBytes28To39 reads the 12 unused bytes in the range 28-39.
func readUnusedBytes28To39(reader io.Reader, buff *bytes.Buffer) error {
	unused := [1]byte{}
	for i := 0; i < 12; i++ {
		l, err := reader.Read(unused[:])
		if err != nil && !errors.Is(err, io.EOF) {
			log.WithError(err).Error("Failed to read unused bytes 28-39")
			return oops.Errorf("reading unused bytes 28-39: %w", err)
		}
		if l != 1 {
			log.WithField("byte_number", 28+i).Error("Missing unused byte")
			return ErrMissingUnusedBytes28To39
		}
		buff.Write(unused[:])
	}
	log.Debug("Read unused bytes 28-39")
	return nil
}

// readVersionAndSignerID reads the version and signer ID strings.
func readVersionAndSignerID(reader io.Reader, su3 *SU3, buff *bytes.Buffer, verLen, signIDLen uint16) error {
	// Version.
	versionBytes := make([]byte, verLen)
	l, err := reader.Read(versionBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read version")
		return oops.Errorf("reading version: %w", err)
	}
	if l != int(verLen) {
		log.Error("Missing version")
		return ErrMissingVersion
	}
	version := strings.TrimRight(string(versionBytes), "\x00")
	su3.Version = version
	buff.Write(versionBytes[:])
	log.WithField("version", version).Debug("Version read")

	// Signer ID.
	signerIDBytes := make([]byte, signIDLen)
	l, err = reader.Read(signerIDBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read signer ID")
		return oops.Errorf("reading signer id: %w", err)
	}
	if l != int(signIDLen) {
		log.Error("Missing signer ID")
		return ErrMissingSignerID
	}
	signerID := string(signerIDBytes)
	su3.SignerID = signerID
	buff.Write(signerIDBytes[:])
	log.WithField("signer_id", signerID).Debug("Signer ID read")

	return nil
}

// initializeReaders creates and configures the content and signature readers.
func initializeReaders(su3 *SU3, sigType SignatureType, buff *bytes.Buffer) error {
	su3.contentReader = &contentReader{
		su3: su3,
	}
	log.Debug("Content reader initialized")

	switch sigType {
	case RSA_SHA256_2048:
		su3.contentReader.hash = sha256.New()
		log.Debug("Using SHA256 hash for content")
	case RSA_SHA512_4096:
		su3.contentReader.hash = sha512.New()
		log.Debug("Using SHA512 hash for content")
	}

	if su3.contentReader.hash != nil {
		su3.contentReader.hash.Write(buff.Bytes())
		log.Debug("Wrote header to content hash")
	}

	su3.signatureReader = &signatureReader{
		su3: su3,
	}

	return nil
}

type fixedLengthReader struct {
	length    uint64
	readSoFar uint64
	reader    io.Reader
}

func (r *fixedLengthReader) Read(p []byte) (n int, err error) {
	if r.readSoFar >= r.length {
		log.Debug("Fixed length reader: EOF reached")
		return 0, io.EOF
	}
	if uint64(len(p)) > r.length-r.readSoFar {
		p = p[:r.length-r.readSoFar]
	}
	n, err = r.reader.Read(p)
	r.readSoFar += uint64(n)
	log.WithFields(logrus.Fields{
		"bytes_read":   n,
		"total_read":   r.readSoFar,
		"total_length": r.length,
	}).Debug("Fixed length reader: Read operation")
	return n, err
}

type contentReader struct {
	su3      *SU3
	reader   *fixedLengthReader
	hash     hash.Hash
	finished bool
}

func (r *contentReader) Read(p []byte) (n int, err error) {
	r.su3.mut.Lock()
	defer r.su3.mut.Unlock()

	if r.finished {
		log.Warn("Attempt to read content after finishing")
		return 0, oops.Errorf("out of bytes, maybe you read the signature before you read the content")
	}

	if r.reader == nil {
		r.reader = &fixedLengthReader{
			length:    r.su3.ContentLength,
			readSoFar: 0,
			reader:    r.su3.reader,
		}
		log.WithField("content_length", r.su3.ContentLength).Debug("Initialized content reader")
	}

	l, err := r.reader.Read(p)

	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Error reading content")
		return l, oops.Errorf("reading content: %w", err)
	} else if errors.Is(err, io.EOF) && r.reader.readSoFar != r.su3.ContentLength {
		log.Error("Content shorter than expected")
		return l, ErrMissingContent
	} else if errors.Is(err, io.EOF) {
		r.finished = true
		log.Debug("Finished reading content")
	}

	if r.hash != nil {
		r.hash.Write(p[:l])
	}

	if r.finished {
		if r.su3.publicKey == nil {
			log.Error("No public key provided for signature verification")
			return l, ErrInvalidSignature
		}
		r.su3.signatureReader.getBytes()
		if r.su3.signatureReader.err != nil {
			log.WithError(r.su3.signatureReader.err).Error("Failed to get signature bytes")
			return l, r.su3.signatureReader.err
		}
		log.WithField("signature_type", r.su3.SignatureType).Debug("Verifying signature")
		// TODO support all signature types
		switch r.su3.SignatureType {
		case RSA_SHA256_2048:
			var pubKey *rsa.PublicKey
			if k, ok := r.su3.publicKey.(*rsa.PublicKey); !ok {
				log.Error("Invalid public key type")
				return l, ErrInvalidPublicKey
			} else {
				pubKey = k
			}
			err := rsa.VerifyPKCS1v15(pubKey, 0, r.hash.Sum(nil), r.su3.signatureReader.bytes)
			if err != nil {
				log.WithError(err).Error("Signature verification failed")
				return l, ErrInvalidSignature
			}
			log.Debug("Signature verified successfully")
		case RSA_SHA512_4096:
			var pubKey *rsa.PublicKey
			if k, ok := r.su3.publicKey.(*rsa.PublicKey); !ok {
				log.Error("Invalid public key type")
				return l, ErrInvalidPublicKey
			} else {
				pubKey = k
			}
			err := rsa.VerifyPKCS1v15(pubKey, 0, r.hash.Sum(nil), r.su3.signatureReader.bytes)
			if err != nil {
				log.WithError(err).Error("Signature verification failed")
				return l, ErrInvalidSignature
			}
			log.Debug("Signature verified successfully")
		default:
			log.WithField("signature_type", r.su3.SignatureType).Error("Unsupported signature type")
			return l, ErrUnsupportedSignatureType
		}
	}

	return l, err
}

type signatureReader struct {
	su3    *SU3
	bytes  []byte
	err    error
	reader io.Reader
}

func (r *signatureReader) getBytes() {
	log.Debug("Getting signature bytes")
	// If content hasn't been read yet, throw it away.
	if !r.su3.contentReader.finished {
		log.Warn("Content not fully read, reading remaining content")
		_, err := ioutil.ReadAll(r.su3.contentReader)
		if err != nil {
			log.WithError(err).Error("Failed to read remaining content")
			r.err = oops.Errorf("reading content: %w", err)
			return
		}
	}

	// Read signature.
	reader := &fixedLengthReader{
		length:    uint64(r.su3.SignatureLength),
		readSoFar: 0,
		reader:    r.su3.reader,
	}
	sigBytes, err := ioutil.ReadAll(reader)

	if err != nil {
		log.WithError(err).Error("Failed to read signature")
		r.err = oops.Errorf("reading signature: %w", err)
	} else if reader.readSoFar != uint64(r.su3.SignatureLength) {
		log.Error("Signature shorter than expected")
		r.err = ErrMissingSignature
	} else {
		r.bytes = sigBytes
		r.reader = bytes.NewReader(sigBytes)
		log.WithField("signature_length", len(sigBytes)).Debug("Signature bytes read successfully")
	}
}

func (r *signatureReader) Read(p []byte) (n int, err error) {
	r.su3.mut.Lock()
	defer r.su3.mut.Unlock()
	if len(r.bytes) == 0 {
		log.Debug("Signature bytes not yet read, getting bytes")
		r.getBytes()
	}
	if r.err != nil {
		log.WithError(r.err).Error("Error encountered while getting signature bytes")
		return 0, r.err
	}
	// return r.reader.Read(p)
	n, err = r.reader.Read(p)
	log.WithField("bytes_read", n).Debug("Read from signature")
	return n, err
}
