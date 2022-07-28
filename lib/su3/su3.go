// Package su3 implements reading the SU3 file format.
//
// SU3 files provide content that is signed by a known identity.
// They are used to distributed many types of data, including reseed files,
// plugins, blocklists, and more.
//
// See: https://geti2p.net/spec/updates#su3-file-specification
//
// The Read() function takes an io.Reader, and it returns four values:
//   - meta: The SU3 file metadata, describing the type of file and the identity that signed it.
//   - content: An io.Reader of the file contents.
//   - signature: An io.Reader of the signature.
//   - err: An error if something went wrong.
//
// Example usage:
//     // Let's say we are reading an SU3 file from an HTTP body.
//     meta, content, signature, err := su3.Read(body)
//     if err != nil {
//         // Handle error.
//     }
//     bytes, err := ioutil.ReadAll(content)
//     if errors.Is(err, su3.ErrInvalidSignature) {
//	       // The signature is invalid.
//     } else if err != nil {
//         // Handle error.
//     }
//
// Note: the content io.Reader must be read *before* the signature io.Reader.
// If you read the signature first, the content bytes will be thrown away.
// If you then attempt to read the content, you will get an error.
// For clarification, see TestReadSignatureFirst.
//
// PLEASE NOTE: Signature validation is not implemented at this time.
// Use with caution.
package su3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

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

var ErrMissingMagicBytes = errors.New("missing magic bytes")
var ErrMissingUnusedByte6 = errors.New("missing unused byte 6")
var ErrMissingFileFormatVersion = errors.New("missing or incorrect file format version")
var ErrMissingSignatureType = errors.New("missing or invalid signature type")
var ErrMissingSignatureLength = errors.New("missing signature length")
var ErrMissingUnusedByte12 = errors.New("missing unused byte 12")
var ErrMissingVersionLength = errors.New("missing version length")
var ErrVersionTooShort = errors.New("version length too short")
var ErrMissingUnusedByte14 = errors.New("missing unused byte 14")
var ErrMissingSignerIDLength = errors.New("missing signer ID length")
var ErrMissingContentLength = errors.New("missing content length")
var ErrMissingUnusedByte24 = errors.New("missing unused byte 24")
var ErrMissingFileType = errors.New("missing or invalid file type")
var ErrMissingUnusedByte26 = errors.New("missing unused byte 26")
var ErrMissingContentType = errors.New("missing or invalid content type")
var ErrMissingUnusedBytes28To39 = errors.New("missing unused bytes 28-39")
var ErrMissingVersion = errors.New("missing version")
var ErrMissingSignerID = errors.New("missing signer ID")
var ErrMissingContent = errors.New("missing content")
var ErrMissingSignature = errors.New("missing signature")
var ErrInvalidSignature = errors.New("invalid signature")

const magicBytes = "I2Psu3"

type SU3Meta struct {
	SignatureType   SignatureType
	SignatureLength uint16
	ContentLength   uint64
	FileType        FileType
	ContentType     ContentType
	Version         string
	SignerID        string
}

func Read(reader io.Reader) (meta *SU3Meta, content io.Reader, signature io.Reader, err error) {
	// Magic bytes.
	mbytes := make([]byte, len(magicBytes))
	l, err := reader.Read(mbytes)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading magic bytes: %w", err)
	}
	if l != len(mbytes) {
		return nil, nil, nil, ErrMissingMagicBytes
	}
	if string(mbytes) != magicBytes {
		return nil, nil, nil, ErrMissingMagicBytes
	}

	// Unused byte 6.
	unused := [1]byte{}
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading unused byte 6: %w", err)
	}
	if l != 1 {
		return nil, nil, nil, ErrMissingUnusedByte6
	}

	// SU3 file format version (always 0).
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading SU3 file format version: %w", err)
	}
	if l != 1 {
		return nil, nil, nil, ErrMissingFileFormatVersion
	}
	if unused[0] != 0x00 {
		return nil, nil, nil, ErrMissingFileFormatVersion
	}

	meta = &SU3Meta{}

	// Signature type.
	sigTypeBytes := [2]byte{}
	l, err = reader.Read(sigTypeBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading signature type: %w", err)
	}
	if l != 2 {
		return nil, nil, nil, ErrMissingSignatureType
	}
	sigType, ok := sigTypes[sigTypeBytes]
	if !ok {
		return nil, nil, nil, ErrMissingSignatureType
	}
	meta.SignatureType = sigType

	// Signature length.
	sigLengthBytes := [2]byte{}
	l, err = reader.Read(sigLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading signature length: %w", err)
	}
	if l != 2 {
		return nil, nil, nil, ErrMissingSignatureLength
	}
	sigLen := binary.BigEndian.Uint16(sigLengthBytes[:])
	// TODO check that sigLen is the correct length for sigType.
	meta.SignatureLength = sigLen

	// Unused byte 12.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading unused byte 12: %w", err)
	}
	if l != 1 {
		return nil, nil, nil, ErrMissingUnusedByte12
	}

	// Version length.
	verLengthBytes := [1]byte{}
	l, err = reader.Read(verLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading version length: %w", err)
	}
	if l != 1 {
		return nil, nil, nil, ErrMissingVersionLength
	}
	verLen := binary.BigEndian.Uint16([]byte{0x00, verLengthBytes[0]})
	if verLen < 16 {
		return nil, nil, nil, ErrVersionTooShort
	}

	// Unused byte 14.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading unused byte 14: %w", err)
	}
	if l != 1 {
		return nil, nil, nil, ErrMissingUnusedByte14
	}

	// Signer ID length.
	sigIDLengthBytes := [1]byte{}
	l, err = reader.Read(sigIDLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading signer id length: %w", err)
	}
	if l != 1 {
		return nil, nil, nil, ErrMissingSignerIDLength
	}
	signIDLen := binary.BigEndian.Uint16([]byte{0x00, sigIDLengthBytes[0]})

	// Content length.
	contentLengthBytes := [8]byte{}
	l, err = reader.Read(contentLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading content length: %w", err)
	}
	if l != 8 {
		return nil, nil, nil, ErrMissingContentLength
	}
	contentLen := binary.BigEndian.Uint64(contentLengthBytes[:])
	meta.ContentLength = contentLen

	// Unused byte 24.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading unused byte 24: %w", err)
	}
	if l != 1 {
		return nil, nil, nil, ErrMissingUnusedByte24
	}

	// File type.
	fileTypeBytes := [1]byte{}
	l, err = reader.Read(fileTypeBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading file type: %w", err)
	}
	if l != 1 {
		return nil, nil, nil, ErrMissingFileType
	}
	fileType, ok := fileTypes[fileTypeBytes[0]]
	if !ok {
		return nil, nil, nil, ErrMissingFileType
	}
	meta.FileType = fileType

	// Unused byte 26.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading unused byte 26: %w", err)
	}
	if l != 1 {
		return nil, nil, nil, ErrMissingUnusedByte26
	}

	// Content type.
	contentTypeBytes := [1]byte{}
	l, err = reader.Read(contentTypeBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading content type: %w", err)
	}
	if l != 1 {
		return nil, nil, nil, ErrMissingContentType
	}
	contentType, ok := contentTypes[contentTypeBytes[0]]
	if !ok {
		return nil, nil, nil, ErrMissingContentType
	}
	meta.ContentType = contentType

	// Unused bytes 28-39.
	for i := 0; i < 12; i++ {
		l, err = reader.Read(unused[:])
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, nil, nil, fmt.Errorf("reading unused bytes 28-39: %w", err)
		}
		if l != 1 {
			return nil, nil, nil, ErrMissingUnusedBytes28To39
		}
	}

	// Version.
	versionBytes := make([]byte, verLen)
	l, err = reader.Read(versionBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading version: %w", err)
	}
	if l != int(verLen) {
		return nil, nil, nil, ErrMissingVersion
	}
	version := strings.TrimRight(string(versionBytes), "\x00")
	meta.Version = version

	// Signer ID.
	signerIDBytes := make([]byte, signIDLen)
	l, err = reader.Read(signerIDBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, fmt.Errorf("reading signer id: %w", err)
	}
	if l != int(signIDLen) {
		return nil, nil, nil, ErrMissingSignerID
	}
	signerID := string(signerIDBytes)
	meta.SignerID = signerID

	csr := &contentSignatureReader{
		reader:          reader,
		contentLength:   contentLen,
		signatureLength: sigLen,
	}

	return meta, csr.Content(), csr.Signature(), nil
}

// contentSignatureReader synchronizes reading the content, and then the signature,
// out of the same io.Reader that we are reading the SU3 file from. It allows us
// to return two io.Readers, one for the content, and one for the signature, and
// have them both be read out of the SU3 file io.Reader.
type contentSignatureReader struct {
	sync.Mutex
	reader          io.Reader
	contentLength   uint64
	signatureLength uint16
	bytesRead       uint64
}

func (csr *contentSignatureReader) Content() io.Reader {
	return &byteReader{
		csr:             csr,
		numBytes:        csr.contentLength,
		startByte:       0,
		outOfBytesError: ErrMissingContent,
	}
}

func (csr *contentSignatureReader) Signature() io.Reader {
	return &byteReader{
		csr:             csr,
		numBytes:        uint64(csr.signatureLength),
		startByte:       csr.contentLength,
		outOfBytesError: ErrMissingSignature,
	}
}

type byteReader struct {
	csr             *contentSignatureReader
	numBytes        uint64
	startByte       uint64
	outOfBytesError error
}

func (br *byteReader) Read(p []byte) (n int, err error) {
	br.csr.Lock()
	defer br.csr.Unlock()
	// If we have already read past where we are supposed to, return an error.
	// This would happen if someone read the signature before reading the content,
	// and then tried to read the content.
	if br.csr.bytesRead > br.startByte {
		return 0, errors.New("out of bytes, maybe you read the signature before you read the content")
	}
	// If we have not read up until where we are supposed to, throw away the bytes.
	// This would happen if someone read the signature before reading the content.
	// We want to allow them to read the signature. The above condition will return
	// an error if they try to read the content.
	if br.csr.bytesRead < br.startByte {
		bytesToThrowAway := br.startByte - br.csr.bytesRead
		throwaway := make([]byte, bytesToThrowAway)
		l, err := br.csr.reader.Read(throwaway)
		br.csr.bytesRead += uint64(l)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, fmt.Errorf("reading throwaway bytes: %w", err)
		}
		if l != int(bytesToThrowAway) {
			return 0, br.outOfBytesError
		}
	}
	// We are at the correct position.
	// If numBytes is 0, we have read all the bytes.
	if br.numBytes == 0 {
		// TODO when we finish reading content, we should then read the signature and verify it.
		// If the signature doesn't match, we would return ErrInvalidSignature here.
		return 0, io.EOF
	}
	// Otherwise, we have some bytes to read.
	numBytesToRead := len(p)
	if numBytesToRead > int(br.numBytes) {
		numBytesToRead = int(br.numBytes)
	}
	l, err := br.csr.reader.Read(p[:numBytesToRead])
	// Advance the counters to keep track of how many bytes we've read.
	br.csr.bytesRead += uint64(l)
	br.numBytes = br.numBytes - uint64(l)
	br.startByte = br.startByte + uint64(l)
	// We should have read the correct number of bytes.
	if l < numBytesToRead {
		return l, br.outOfBytesError
	}
	return l, err
}
