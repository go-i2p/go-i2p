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
//     // Let's say we are reading an SU3 file from an HTTP body, which is an io.Reader.
//     su3File, err := su3.Read(body)
//     if err != nil {
//         // Handle error.
//     }
//     // Look up this signer's key.
//     key := somehow_lookup_the_key(su3File.SignerID)
//     // Read the content.
//     contentReader := su3File.Content(key)
//     bytes, err := ioutil.ReadAll(contentReader)
//     if errors.Is(err, su3.ErrInvalidSignature) {
//	       // The signature is invalid, OR a nil key was provided.
//     } else if err != nil {
//         // Handle error.
//     }
//
// If you want to parse from a []byte, you can wrap them like this:
//     mySU3FileBytes := []byte{0x00, 0x01, 0x02, 0x03}
//     su3File, err := su3.Read(bytes.NewReader(mySU3FileBytes))
//
// Note: if you want to read the content, the Content() io.Reader must be read
// *before* the Signature() io.Reader. If you read the signature first, the
// content bytes will be thrown away. If you then attempt to read the content,
// you will get an error. For clarification, see TestReadSignatureFirst.
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
	bytesRead       uint64
	publicKey       interface{}
	contentReader   *su3Reader
	signatureReader *su3Reader
}

func (su3 *SU3) Content(publicKey interface{}) io.Reader {
	su3.publicKey = publicKey
	return su3.contentReader
}

func (su3 *SU3) Signature() io.Reader {
	return su3.signatureReader
}

func Read(reader io.Reader) (su3 *SU3, err error) {
	// Magic bytes.
	mbytes := make([]byte, len(magicBytes))
	l, err := reader.Read(mbytes)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading magic bytes: %w", err)
	}
	if l != len(mbytes) {
		return nil, ErrMissingMagicBytes
	}
	if string(mbytes) != magicBytes {
		return nil, ErrMissingMagicBytes
	}

	// Unused byte 6.
	unused := [1]byte{}
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading unused byte 6: %w", err)
	}
	if l != 1 {
		return nil, ErrMissingUnusedByte6
	}

	// SU3 file format version (always 0).
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading SU3 file format version: %w", err)
	}
	if l != 1 {
		return nil, ErrMissingFileFormatVersion
	}
	if unused[0] != 0x00 {
		return nil, ErrMissingFileFormatVersion
	}

	su3 = &SU3{
		mut:    sync.Mutex{},
		reader: reader,
	}

	// Signature type.
	sigTypeBytes := [2]byte{}
	l, err = reader.Read(sigTypeBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading signature type: %w", err)
	}
	if l != 2 {
		return nil, ErrMissingSignatureType
	}
	sigType, ok := sigTypes[sigTypeBytes]
	if !ok {
		return nil, ErrMissingSignatureType
	}
	su3.SignatureType = sigType

	// Signature length.
	sigLengthBytes := [2]byte{}
	l, err = reader.Read(sigLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading signature length: %w", err)
	}
	if l != 2 {
		return nil, ErrMissingSignatureLength
	}
	sigLen := binary.BigEndian.Uint16(sigLengthBytes[:])
	// TODO check that sigLen is the correct length for sigType.
	su3.SignatureLength = sigLen

	// Unused byte 12.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading unused byte 12: %w", err)
	}
	if l != 1 {
		return nil, ErrMissingUnusedByte12
	}

	// Version length.
	verLengthBytes := [1]byte{}
	l, err = reader.Read(verLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading version length: %w", err)
	}
	if l != 1 {
		return nil, ErrMissingVersionLength
	}
	verLen := binary.BigEndian.Uint16([]byte{0x00, verLengthBytes[0]})
	if verLen < 16 {
		return nil, ErrVersionTooShort
	}

	// Unused byte 14.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading unused byte 14: %w", err)
	}
	if l != 1 {
		return nil, ErrMissingUnusedByte14
	}

	// Signer ID length.
	sigIDLengthBytes := [1]byte{}
	l, err = reader.Read(sigIDLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading signer id length: %w", err)
	}
	if l != 1 {
		return nil, ErrMissingSignerIDLength
	}
	signIDLen := binary.BigEndian.Uint16([]byte{0x00, sigIDLengthBytes[0]})

	// Content length.
	contentLengthBytes := [8]byte{}
	l, err = reader.Read(contentLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading content length: %w", err)
	}
	if l != 8 {
		return nil, ErrMissingContentLength
	}
	contentLen := binary.BigEndian.Uint64(contentLengthBytes[:])
	su3.ContentLength = contentLen

	// Unused byte 24.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading unused byte 24: %w", err)
	}
	if l != 1 {
		return nil, ErrMissingUnusedByte24
	}

	// File type.
	fileTypeBytes := [1]byte{}
	l, err = reader.Read(fileTypeBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading file type: %w", err)
	}
	if l != 1 {
		return nil, ErrMissingFileType
	}
	fileType, ok := fileTypes[fileTypeBytes[0]]
	if !ok {
		return nil, ErrMissingFileType
	}
	su3.FileType = fileType

	// Unused byte 26.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading unused byte 26: %w", err)
	}
	if l != 1 {
		return nil, ErrMissingUnusedByte26
	}

	// Content type.
	contentTypeBytes := [1]byte{}
	l, err = reader.Read(contentTypeBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading content type: %w", err)
	}
	if l != 1 {
		return nil, ErrMissingContentType
	}
	contentType, ok := contentTypes[contentTypeBytes[0]]
	if !ok {
		return nil, ErrMissingContentType
	}
	su3.ContentType = contentType

	// Unused bytes 28-39.
	for i := 0; i < 12; i++ {
		l, err = reader.Read(unused[:])
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("reading unused bytes 28-39: %w", err)
		}
		if l != 1 {
			return nil, ErrMissingUnusedBytes28To39
		}
	}

	// Version.
	versionBytes := make([]byte, verLen)
	l, err = reader.Read(versionBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading version: %w", err)
	}
	if l != int(verLen) {
		return nil, ErrMissingVersion
	}
	version := strings.TrimRight(string(versionBytes), "\x00")
	su3.Version = version

	// Signer ID.
	signerIDBytes := make([]byte, signIDLen)
	l, err = reader.Read(signerIDBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading signer id: %w", err)
	}
	if l != int(signIDLen) {
		return nil, ErrMissingSignerID
	}
	signerID := string(signerIDBytes)
	su3.SignerID = signerID

	// Track the number of bytes read so that the su3Readers know their position.
	su3.bytesRead = uint64(39 + int(verLen) + int(signIDLen))

	su3.contentReader = &su3Reader{
		su3:             su3,
		startByte:       su3.bytesRead,
		numBytes:        su3.ContentLength,
		outOfBytesError: ErrMissingContent,
	}

	su3.signatureReader = &su3Reader{
		su3:             su3,
		startByte:       su3.bytesRead + su3.ContentLength,
		numBytes:        uint64(su3.SignatureLength),
		outOfBytesError: ErrMissingSignature,
	}

	return su3, nil
}

type su3Reader struct {
	su3             *SU3
	startByte       uint64
	numBytes        uint64
	outOfBytesError error
}

func (r *su3Reader) Read(p []byte) (n int, err error) {
	r.su3.mut.Lock()
	defer r.su3.mut.Unlock()

	// If we have already read past where we are supposed to, return an error.
	// This would happen if someone read the signature before reading the content,
	// and then tried to read the content.
	if r.su3.bytesRead > r.startByte {
		return 0, errors.New("out of bytes, maybe you read the signature before you read the content")
	}

	// If we have not read up until where we are supposed to, throw away the bytes.
	// This would happen if someone read the signature before reading the content.
	// We want to allow them to read the signature. The above condition will return
	// an error if they try to read the content after the bytes have been thrown away.
	if r.su3.bytesRead < r.startByte {
		bytesToThrowAway := r.startByte - r.su3.bytesRead
		throwaway := make([]byte, bytesToThrowAway)
		l, err := r.su3.reader.Read(throwaway)
		r.su3.bytesRead += uint64(l)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, fmt.Errorf("reading throwaway bytes: %w", err)
		}
		if l != int(bytesToThrowAway) {
			return 0, r.outOfBytesError
		}
	}

	// We are at the correct position.
	// If numBytes is 0, we have read all the bytes.
	if r.numBytes == 0 {
		// TODO when we finish reading content, we should then read the signature and verify it.
		// If the signature doesn't match, we would return ErrInvalidSignature here.
		return 0, io.EOF
	}

	// Otherwise, we have some bytes to read.
	numBytesToRead := len(p)
	if numBytesToRead > int(r.numBytes) {
		numBytesToRead = int(r.numBytes)
	}
	l, err := r.su3.reader.Read(p[:numBytesToRead])

	// Advance the counters to keep track of how many bytes we've read.
	r.su3.bytesRead += uint64(l)
	r.numBytes = r.numBytes - uint64(l)
	r.startByte = r.startByte + uint64(l)

	// We should have read the correct number of bytes.
	if l < numBytesToRead {
		return l, r.outOfBytesError
	}

	return l, err
}
