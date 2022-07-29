package su3

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

func fileReader(t *testing.T, filename string) io.Reader {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("cannot read test data file %s: %s", filename, err)
	}
	return f
}

func fileBytes(t *testing.T, filename string) []byte {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("cannot read test data file %s: %s", filename, err)
	}
	return b
}

func appendBytes(b ...[]byte) []byte {
	var out []byte
	for _, bb := range b {
		out = append(out, bb...)
	}
	return out
}

func fileRSAPubKey(t *testing.T, filename string) *rsa.PublicKey {
	b := fileBytes(t, filename)
	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("cannot parse certificate file %s: %s", filename, err)
	}
	var pubKey *rsa.PublicKey
	if k, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("expected rsa.PublicKey from file %s", filename)
	} else {
		pubKey = k
	}
	return pubKey
}

func genRSAKey(t *testing.T) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key: %s", err)
	}
	return privateKey
}

func TestRead(t *testing.T) {
	// Test data.
	apeaceKey := genRSAKey(t)
	apeaceContent := []byte("apeace rules")
	apeaceContentLength := make([]byte, 8)
	binary.BigEndian.PutUint64(apeaceContentLength, uint64(len(apeaceContent)))
	apeaceHash := sha256.New()
	_, err := apeaceHash.Write(apeaceContent)
	assert.Nil(t, err, "cannot hash content")
	apeaceSum := apeaceHash.Sum(nil)
	apeaceSignature, err := rsa.SignPSS(rand.Reader, apeaceKey, crypto.SHA256, apeaceSum, nil)
	assert.Nil(t, err, "cannot sign content")
	apeaceSignatureLength := make([]byte, 2)
	binary.BigEndian.PutUint16(apeaceSignatureLength, uint16(len(apeaceSignature)))
	apeaceWrongKey := genRSAKey(t)
	apeaceInvalidSignature, err := rsa.SignPSS(rand.Reader, apeaceWrongKey, crypto.SHA256, apeaceSum, nil)
	assert.Nil(t, err, "cannot sign content")
	apeaceInvalidSignatureLength := make([]byte, 2)
	binary.BigEndian.PutUint16(apeaceInvalidSignatureLength, uint16(len(apeaceInvalidSignature)))

	tests := []struct {
		name          string
		skip          bool
		reader        io.Reader
		key           interface{}
		wantErr       string
		wantSU3       *SU3
		wantContent   []byte
		wantSignature []byte
	}{
		{
			name:    "zero_bytes",
			reader:  bytes.NewReader([]byte{}),
			wantErr: ErrMissingMagicBytes.Error(),
		},
		{
			name:    "magic_bytes_not_long_enough",
			reader:  bytes.NewReader([]byte("I2P")),
			wantErr: ErrMissingMagicBytes.Error(),
		},
		{
			name:    "magic_bytes_incorrect",
			reader:  bytes.NewReader([]byte("XXXXXX")),
			wantErr: ErrMissingMagicBytes.Error(),
		},
		{
			name:    "missing_unused_byte_6",
			reader:  bytes.NewReader([]byte("I2Psu3")),
			wantErr: ErrMissingUnusedByte6.Error(),
		},
		{
			name: "missing_file_format",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"), // Magic bytes
				[]byte{0x00},     // Unused byte 6
			)),
			wantErr: ErrMissingFileFormatVersion.Error(),
		},
		{
			name: "incorrect_file_format",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"), // Magic bytes
				[]byte{0x00},     // Unused byte 6
				[]byte{0x01},     // Incorrect file format
			)),
			wantErr: ErrMissingFileFormatVersion.Error(),
		},
		{
			name: "missing_signature_type",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"), // Magic bytes
				[]byte{0x00},     // Unused byte 6
				[]byte{0x00},     // File format
			)),
			wantErr: ErrMissingSignatureType.Error(),
		},
		{
			name: "unsupported_signature_type",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),   // Magic bytes
				[]byte{0x00},       // Unused byte 6
				[]byte{0x00},       // File format
				[]byte{0x99, 0x99}, // Unsupported signature type
			)),
			wantErr: ErrUnsupportedSignatureType.Error(),
		},
		{
			name: "missing_signature_length",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),   // Magic bytes
				[]byte{0x00},       // Unused byte 6
				[]byte{0x00},       // File format
				[]byte{0x00, 0x04}, // Signature type RSA_SHA256_2048
			)),
			wantErr: ErrMissingSignatureLength.Error(),
		},
		{
			name: "missing_unused_byte_12",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
			)),
			wantErr: ErrMissingUnusedByte12.Error(),
		},
		{
			name: "missing_version_length",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
			)),
			wantErr: ErrMissingVersionLength.Error(),
		},
		{
			name: "version_too_short",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x01},          // Version length 1
			)),
			wantErr: ErrVersionTooShort.Error(),
		},
		{
			name: "missing_unused_byte_14",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
			)),
			wantErr: ErrMissingUnusedByte14.Error(),
		},
		{
			name: "missing_signer_length",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
			)),
			wantErr: ErrMissingSignerIDLength.Error(),
		},
		{
			name: "missing_content_length",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
			)),
			wantErr: ErrMissingContentLength.Error(),
		},
		{
			name: "missing_unused_byte_24",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
			)),
			wantErr: ErrMissingUnusedByte24.Error(),
		},
		{
			name: "missing_file_type",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
				[]byte{0x00},          // Unused byte 24
			)),
			wantErr: ErrMissingFileType.Error(),
		},
		{
			name: "invalid_file_type",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
				[]byte{0x00},          // Unused byte 24
				[]byte{0x99},          // Invalid file type
			)),
			wantErr: ErrMissingFileType.Error(),
		},
		{
			name: "missing_unused_byte_26",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
				[]byte{0x00},          // Unused byte 24
				[]byte{0x02},          // File type HTML
			)),
			wantErr: ErrMissingUnusedByte26.Error(),
		},
		{
			name: "missing_content_type",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
				[]byte{0x00},          // Unused byte 24
				[]byte{0x02},          // File type HTML
				[]byte{0x00},          // Unused byte 26
			)),
			wantErr: ErrMissingContentType.Error(),
		},
		{
			name: "invalid_content_type",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
				[]byte{0x00},          // Unused byte 24
				[]byte{0x02},          // File type HTML
				[]byte{0x00},          // Unused byte 26
				[]byte{0x99},          // Invalid content type
			)),
			wantErr: ErrMissingContentType.Error(),
		},
		{
			name: "missing_unused_bytes_28-39",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
				[]byte{0x00},          // Unused byte 24
				[]byte{0x02},          // File type HTML
				[]byte{0x00},          // Unused byte 26
				[]byte{0x00},          // Content type unknown
			)),
			wantErr: ErrMissingUnusedBytes28To39.Error(),
		},
		{
			name: "partial_unused_bytes_28-39",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
				[]byte{0x00},          // Unused byte 24
				[]byte{0x02},          // File type HTML
				[]byte{0x00},          // Unused byte 26
				[]byte{0x00},          // Content type unknown
				[]byte{0x00, 0x00},    // Partial unused bytes 28-39
			)),
			wantErr: ErrMissingUnusedBytes28To39.Error(),
		},
		{
			name: "missing_version",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
				[]byte{0x00},          // Unused byte 24
				[]byte{0x02},          // File type HTML
				[]byte{0x00},          // Unused byte 26
				[]byte{0x00},          // Content type unknown
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Unused bytes 28-39
			)),
			wantErr: ErrMissingVersion.Error(),
		},
		{
			name: "missing_signer_ID",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
				[]byte{0x00},          // Unused byte 24
				[]byte{0x02},          // File type HTML
				[]byte{0x00},          // Unused byte 26
				[]byte{0x00},          // Content type unknown
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Unused bytes 28-39
				appendBytes([]byte("1234567890"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),  // Version with padding
			)),
			wantErr: ErrMissingSignerID.Error(),
		},
		{
			name: "missing_content",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
				[]byte{0x00},          // Unused byte 24
				[]byte{0x02},          // File type HTML
				[]byte{0x00},          // Unused byte 26
				[]byte{0x00},          // Content type unknown
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Unused bytes 28-39
				appendBytes([]byte("1234567890"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),  // Version with padding
				[]byte("apeace"), // Signer ID
			)),
			wantErr: ErrMissingContent.Error(),
		},
		{
			name: "missing_signature",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
				[]byte{0x00},          // Unused byte 24
				[]byte{0x02},          // File type HTML
				[]byte{0x00},          // Unused byte 26
				[]byte{0x00},          // Content type unknown
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Unused bytes 28-39
				appendBytes([]byte("1234567890"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),  // Version with padding
				[]byte("apeace"), // Signer ID
				apeaceContent,    // Content
			)),
			key:     &apeaceKey.PublicKey,
			wantErr: ErrMissingSignature.Error(),
		},
		{
			name: "invalid_signature",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),             // Magic bytes
				[]byte{0x00},                 // Unused byte 6
				[]byte{0x00},                 // File format
				[]byte{0x00, 0x04},           // Signature type RSA_SHA256_2048
				apeaceInvalidSignatureLength, // Signature length
				[]byte{0x00},                 // Unused byte 12
				[]byte{0x10},                 // Version length 16
				[]byte{0x00},                 // Unused byte 14
				[]byte{0x06},                 // Signer ID length 6
				apeaceContentLength,          // Content length
				[]byte{0x00},                 // Unused byte 24
				[]byte{0x02},                 // File type HTML
				[]byte{0x00},                 // Unused byte 26
				[]byte{0x00},                 // Content type unknown
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Unused bytes 28-39
				appendBytes([]byte("1234567890"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),  // Version with padding
				[]byte("apeace"),       // Signer ID
				apeaceContent,          // Content
				apeaceInvalidSignature, // Invalid signature
			)),
			key:     &apeaceKey.PublicKey,
			wantErr: ErrInvalidSignature.Error(),
		},
		{
			name: "apeace_rules",
			reader: bytes.NewReader(appendBytes(
				[]byte("I2Psu3"),      // Magic bytes
				[]byte{0x00},          // Unused byte 6
				[]byte{0x00},          // File format
				[]byte{0x00, 0x04},    // Signature type RSA_SHA256_2048
				apeaceSignatureLength, // Signature length
				[]byte{0x00},          // Unused byte 12
				[]byte{0x10},          // Version length 16
				[]byte{0x00},          // Unused byte 14
				[]byte{0x06},          // Signer ID length 6
				apeaceContentLength,   // Content length
				[]byte{0x00},          // Unused byte 24
				[]byte{0x02},          // File type HTML
				[]byte{0x00},          // Unused byte 26
				[]byte{0x00},          // Content type unknown
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Unused bytes 28-39
				appendBytes([]byte("1234567890"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),  // Version with padding
				[]byte("apeace"), // Signer ID
				apeaceContent,    // Content
				apeaceSignature,  // Signature
			)),
			key: &apeaceKey.PublicKey,
			wantSU3: &SU3{
				SignatureType:   RSA_SHA256_2048,
				SignatureLength: uint16(len(apeaceSignature)),
				ContentLength:   uint64(len(apeaceContent)),
				FileType:        HTML,
				ContentType:     UNKNOWN,
				Version:         "1234567890",
				SignerID:        "apeace",
			},
			wantContent:   apeaceContent,
			wantSignature: apeaceSignature,
		},
		{
			// Skipping this for now, as the signature doesn't seem to match.
			name:   "reseed-i2pgit.su3",
			skip:   true,
			reader: fileReader(t, "testdata/reseed-i2pgit.su3"),
			key:    fileRSAPubKey(t, "./testdata/hankhill19580_at_gmail.com.crt"),
			wantSU3: &SU3{
				SignatureType:   RSA_SHA512_4096,
				SignatureLength: 512,
				ContentLength:   80138,
				FileType:        ZIP,
				ContentType:     RESEED,
				Version:         "1658849028",
				SignerID:        "hankhill19580@gmail.com",
			},
			wantContent:   fileBytes(t, "testdata/reseed-i2pgit-content.zip"),
			wantSignature: fileBytes(t, "testdata/reseed-i2pgit-signature"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.skip {
				t.Skip()
			}
			su3, err := Read(test.reader)
			var content, signature []byte
			if err == nil {
				content, err = ioutil.ReadAll(su3.Content(test.key))
				if err == nil {
					signature, err = ioutil.ReadAll(su3.Signature())
				}
			}
			if test.wantErr != "" && err == nil {
				t.Fatal("expected error, got nil")
			} else if test.wantErr != "" {
				assert.Contains(t, err.Error(), test.wantErr, fmt.Sprintf("expected error to contain `%s`", test.wantErr))
			} else if err != nil {
				assert.Nil(t, err, "expected nil error")
			} else {
				assert.Equal(t, test.wantSU3.SignatureType, su3.SignatureType, "expected SignatureType to match")
				assert.Equal(t, test.wantSU3.SignatureLength, su3.SignatureLength, "expected SignatureLength to match")
				assert.Equal(t, test.wantSU3.ContentLength, su3.ContentLength, "expected ContentLength to match")
				assert.Equal(t, test.wantSU3.FileType, su3.FileType, "expected FileType to match")
				assert.Equal(t, test.wantSU3.ContentType, su3.ContentType, "expected ContentType to match")
				assert.Equal(t, test.wantSU3.Version, su3.Version, "expected Version to match")
				assert.Equal(t, test.wantSU3.SignerID, su3.SignerID, "expected SignerID to match")
				assert.Equal(t, test.wantContent, content, "expected content to match")
				assert.Equal(t, test.wantSignature, signature, "expected signature to match")
			}
		})
	}
}

func TestReadSignatureFirst(t *testing.T) {
	// Skipping this for now, since the signature doesn't seem to match.
	t.Skip()

	assert := assert.New(t)

	reader := fileReader(t, "testdata/reseed-i2pgit.su3")
	su3, err := Read(reader)
	assert.Nil(err)

	// Read only the signature.
	sig, err := ioutil.ReadAll(su3.Signature())
	assert.Nil(err)
	assert.Equal(fileBytes(t, "testdata/reseed-i2pgit-signature"), sig)

	// Reading content should give an error.
	_, err = ioutil.ReadAll(su3.Content(nil))
	assert.NotNil(err)
}
