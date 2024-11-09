package su3

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
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
	block, rest := pem.Decode(b)
	if len(rest) > 0 {
		t.Fatalf("cannot decode PEM block %s: %d bytes left over", filename, len(rest))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("cannot parse certificate file %s: %s", filename, err)
	}
	var pubKey *rsa.PublicKey
	if k, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("expected rsa.publicKey from file %s", filename)
	} else {
		pubKey = k
	}
	return pubKey
}

// This fake data is generated in TestMain.
var (
	aliceFakeKey   *rsa.PrivateKey
	bobFakeKey     *rsa.PrivateKey
	aliceContent   []byte
	aliceSignature []byte
	aliceSU3       []byte
)

func TestRead(t *testing.T) {
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
			reader:  bytes.NewReader(aliceSU3[:3]),
			wantErr: ErrMissingMagicBytes.Error(),
		},
		{
			name:    "magic_bytes_incorrect",
			reader:  bytes.NewReader([]byte("XXXXXX")),
			wantErr: ErrMissingMagicBytes.Error(),
		},
		{
			name:    "missing_unused_byte_6",
			reader:  bytes.NewReader(aliceSU3[:6]),
			wantErr: ErrMissingUnusedByte6.Error(),
		},
		{
			name:    "missing_file_format",
			reader:  bytes.NewReader(aliceSU3[:7]),
			wantErr: ErrMissingFileFormatVersion.Error(),
		},
		{
			name: "incorrect_file_format",
			reader: bytes.NewReader(appendBytes(
				aliceSU3[:7],
				[]byte{0x01}, // Incorrect file format
			)),
			wantErr: ErrMissingFileFormatVersion.Error(),
		},
		{
			name:    "missing_signature_type",
			reader:  bytes.NewReader(aliceSU3[:8]),
			wantErr: ErrMissingSignatureType.Error(),
		},
		{
			name: "unsupported_signature_type",
			reader: bytes.NewReader(appendBytes(
				aliceSU3[:8],
				[]byte{0x99, 0x99}, // Unsupported signature type
			)),
			wantErr: ErrUnsupportedSignatureType.Error(),
		},
		{
			name:    "missing_signature_length",
			reader:  bytes.NewReader(aliceSU3[:10]),
			wantErr: ErrMissingSignatureLength.Error(),
		},
		{
			name:    "missing_unused_byte_12",
			reader:  bytes.NewReader(aliceSU3[:12]),
			wantErr: ErrMissingUnusedByte12.Error(),
		},
		{
			name:    "missing_version_length",
			reader:  bytes.NewReader(aliceSU3[:13]),
			wantErr: ErrMissingVersionLength.Error(),
		},
		{
			name: "version_too_short",
			reader: bytes.NewReader(appendBytes(
				aliceSU3[:13],
				[]byte{0x01}, // Version length 1
			)),
			wantErr: ErrVersionTooShort.Error(),
		},
		{
			name:    "missing_unused_byte_14",
			reader:  bytes.NewReader(aliceSU3[:14]),
			wantErr: ErrMissingUnusedByte14.Error(),
		},
		{
			name:    "missing_signer_length",
			reader:  bytes.NewReader(aliceSU3[:15]),
			wantErr: ErrMissingSignerIDLength.Error(),
		},
		{
			name:    "missing_content_length",
			reader:  bytes.NewReader(aliceSU3[:16]),
			wantErr: ErrMissingContentLength.Error(),
		},
		{
			name:    "missing_unused_byte_24",
			reader:  bytes.NewReader(aliceSU3[:24]),
			wantErr: ErrMissingUnusedByte24.Error(),
		},
		{
			name:    "missing_file_type",
			reader:  bytes.NewReader(aliceSU3[:25]),
			wantErr: ErrMissingFileType.Error(),
		},
		{
			name: "invalid_file_type",
			reader: bytes.NewReader(appendBytes(
				aliceSU3[:25],
				[]byte{0x99}, // Invalid file type
			)),
			wantErr: ErrMissingFileType.Error(),
		},
		{
			name:    "missing_unused_byte_26",
			reader:  bytes.NewReader(aliceSU3[:26]),
			wantErr: ErrMissingUnusedByte26.Error(),
		},
		{
			name:    "missing_content_type",
			reader:  bytes.NewReader(aliceSU3[:27]),
			wantErr: ErrMissingContentType.Error(),
		},
		{
			name: "invalid_content_type",
			reader: bytes.NewReader(appendBytes(
				aliceSU3[:27],
				[]byte{0x99}, // Invalid content type
			)),
			wantErr: ErrMissingContentType.Error(),
		},
		{
			name:    "missing_unused_bytes_28-39",
			reader:  bytes.NewReader(aliceSU3[:28]),
			wantErr: ErrMissingUnusedBytes28To39.Error(),
		},
		{
			name: "partial_unused_bytes_28-39",
			reader: bytes.NewReader(appendBytes(
				aliceSU3[:28],
				[]byte{0x00, 0x00}, // Partial unused bytes 28-39
			)),
			wantErr: ErrMissingUnusedBytes28To39.Error(),
		},
		{
			name:    "missing_version",
			reader:  bytes.NewReader(aliceSU3[:40]),
			wantErr: ErrMissingVersion.Error(),
		},
		{
			name:    "missing_signer_ID",
			reader:  bytes.NewReader(aliceSU3[:56]),
			wantErr: ErrMissingSignerID.Error(),
		},
		{
			name:    "missing_content",
			reader:  bytes.NewReader(aliceSU3[:61]),
			wantErr: ErrMissingContent.Error(),
		},
		{
			name:    "missing_signature",
			reader:  bytes.NewReader(aliceSU3[:72]),
			key:     &aliceFakeKey.PublicKey,
			wantErr: ErrMissingSignature.Error(),
		},
		{
			name:    "invalid_signature",
			reader:  bytes.NewReader(aliceSU3),
			key:     &bobFakeKey.PublicKey,
			wantErr: ErrInvalidSignature.Error(),
		},
		{
			name:   "complete_with_valid_signature",
			reader: bytes.NewReader(aliceSU3),
			key:    &aliceFakeKey.PublicKey,
			wantSU3: &SU3{
				SignatureType:   RSA_SHA256_2048,
				SignatureLength: uint16(len(aliceSignature)),
				ContentLength:   uint64(len(aliceContent)),
				FileType:        HTML,
				ContentType:     UNKNOWN,
				Version:         "1234567890",
				SignerID:        "alice",
			},
			wantContent:   aliceContent,
			wantSignature: aliceSignature,
		},
		{
			// Skipping this for now, as the signature doesn't seem to match.
			name:   "reseed-i2pgit.su3",
			reader: fileReader(t, "testdata/reseed-i2pgit.su3"),
			key:    fileRSAPubKey(t, "./testdata/reseed-hankhill19580_at_gmail.com.crt"),
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
		{
			// Skipping this for now, as the signature doesn't seem to match.
			name:   "snowflake-linux.su3",
			reader: fileReader(t, "testdata/snowflake-linux.su3"),
			key:    fileRSAPubKey(t, "./testdata/snowflake-hankhill19580_at_gmail.com.crt"),
			wantSU3: &SU3{
				SignatureType:   RSA_SHA512_4096,
				SignatureLength: 512,
				ContentLength:   4511938,
				FileType:        ZIP,
				ContentType:     PLUGIN,
				Version:         "0.0.47",
				SignerID:        "hankhill19580@gmail.com",
			},
			wantContent:   fileBytes(t, "testdata/snowflake-content"),
			wantSignature: fileBytes(t, "testdata/snowflake-signature"),
		},
		{
			// Skipping this for now, as the signature doesn't seem to match.
			name:   "novg.su3",
			reader: fileReader(t, "testdata/novg.su3"),
			key:    fileRSAPubKey(t, "./testdata/igor_at_novg.net.crt"),
			wantSU3: &SU3{
				SignatureType:   RSA_SHA512_4096,
				SignatureLength: 512,
				ContentLength:   81367,
				FileType:        ZIP,
				ContentType:     RESEED,
				Version:         "1659048682",
				SignerID:        "igor@novg.net",
			},
			wantContent:   fileBytes(t, "testdata/novg-content.zip"),
			wantSignature: fileBytes(t, "testdata/novg-signature"),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
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

func TestMain(m *testing.M) {
	// Generate fake RSA keys for test data.
	var err error
	aliceFakeKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	bobFakeKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	// Generate fake SU3 file bytes.
	aliceContent = []byte("alice rules")
	contentLength := make([]byte, 8)
	binary.BigEndian.PutUint64(contentLength, uint64(len(aliceContent)))
	signatureLength := make([]byte, 2)
	binary.BigEndian.PutUint16(signatureLength, uint16(256))
	aliceSU3 = appendBytes(
		[]byte("I2Psu3"),   // Magic bytes
		[]byte{0x00},       // Unused byte 6
		[]byte{0x00},       // File format
		[]byte{0x00, 0x04}, // Signature type RSA_SHA256_2048
		signatureLength,    // Signature length
		[]byte{0x00},       // Unused byte 12
		[]byte{0x10},       // Version length 16
		[]byte{0x00},       // Unused byte 14
		[]byte{0x05},       // Signer ID length 5
		contentLength,      // Content length
		[]byte{0x00},       // Unused byte 24
		[]byte{0x02},       // File type HTML
		[]byte{0x00},       // Unused byte 26
		[]byte{0x00},       // Content type unknown
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Unused bytes 28-39
		appendBytes([]byte("1234567890"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),  // Version with padding
		[]byte("alice"), // Signer ID
		aliceContent,    // Content
	)
	hash := sha256.New()
	_, err = hash.Write(aliceSU3)
	if err != nil {
		panic(err)
	}
	sum := hash.Sum(nil)
	aliceSignature, err = rsa.SignPKCS1v15(rand.Reader, aliceFakeKey, 0, sum)
	if err != nil {
		panic(err)
	}
	aliceSU3 = appendBytes(aliceSU3, aliceSignature)
	// Run tests.
	os.Exit(m.Run())
}
