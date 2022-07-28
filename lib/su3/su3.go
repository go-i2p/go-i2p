package su3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
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

const magicBytes = "I2Psu3"

type SU3 struct {
	signatureType   SignatureType
	signatureLength uint16
	versionLength   uint8
	signerIDLength  uint8
	contentLength   uint64
	fileType        FileType
	contentType     ContentType
	version         string
	signerID        string
	content         []byte
	signature       []byte
}

func Read(reader io.Reader) (*SU3, error) {
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

	su3 := &SU3{}

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
	su3.signatureType = sigType

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
	su3.signatureLength = sigLen

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
	su3.versionLength = uint8(verLen)

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
	su3.signerIDLength = uint8(signIDLen)

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
	su3.contentLength = contentLen

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
	su3.fileType = fileType

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
	su3.contentType = contentType

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
	su3.version = version

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
	su3.signerID = signerID

	// Content.
	contentBytes := make([]byte, contentLen)
	l, err = reader.Read(contentBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading content: %w", err)
	}
	if l != int(contentLen) {
		return nil, ErrMissingContent
	}
	su3.content = contentBytes

	// Signature.
	signatureBytes := make([]byte, sigLen)
	l, err = reader.Read(signatureBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading signature: %w", err)
	}
	if l != int(sigLen) {
		return nil, ErrMissingSignature
	}
	// TODO check that signature is correct
	su3.signature = signatureBytes

	return su3, nil
}
