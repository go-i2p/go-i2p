package router_info

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"github.com/go-i2p/go-i2p/lib/common/key_certificate"
	"github.com/go-i2p/go-i2p/lib/common/keys_and_cert"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/common/signature"

	"github.com/go-i2p/go-i2p/lib/common/certificate"
	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_address"
	"github.com/go-i2p/go-i2p/lib/common/router_identity"
	"github.com/go-i2p/go-i2p/lib/crypto"
	"golang.org/x/crypto/openpgp/elgamal"
)

func TestCreateRouterInfo(t *testing.T) {
	// Generate signing key pair (Ed25519)
	var ed25519_privkey crypto.Ed25519PrivateKey
	_, err := (&ed25519_privkey).Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v\n", err)
	}
	ed25519_pubkey_raw, err := ed25519_privkey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v\n", err)
	}
	ed25519_pubkey, ok := ed25519_pubkey_raw.(crypto.SigningPublicKey)
	if !ok {
		t.Fatalf("Failed to get SigningPublicKey from Ed25519 public key")
	}

	// Generate encryption key pair (ElGamal)
	var elgamal_privkey elgamal.PrivateKey
	err = crypto.ElgamalGenerate(&elgamal_privkey, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal private key: %v\n", err)
	}

	// Convert elgamal private key to crypto.ElgPrivateKey
	var elg_privkey crypto.ElgPrivateKey
	xBytes := elgamal_privkey.X.Bytes()
	if len(xBytes) > 256 {
		t.Fatalf("ElGamal private key X too large")
	}
	copy(elg_privkey[256-len(xBytes):], xBytes)

	// Convert elgamal public key to crypto.ElgPublicKey
	var elg_pubkey crypto.ElgPublicKey
	yBytes := elgamal_privkey.PublicKey.Y.Bytes()
	if len(yBytes) > 256 {
		t.Fatalf("ElGamal public key Y too large")
	}
	copy(elg_pubkey[256-len(yBytes):], yBytes)

	// Ensure that elg_pubkey implements crypto.PublicKey interface
	var _ crypto.PublicKey = elg_pubkey

	// Create KeyCertificate specifying key types
	var payload bytes.Buffer

	signingPublicKeyType, err := data.NewIntegerFromInt(7, 2)
	if err != nil {
		t.Fatalf("Failed to create signing public key type integer: %v", err)
	}

	cryptoPublicKeyType, err := data.NewIntegerFromInt(0, 2)
	if err != nil {
		t.Fatalf("Failed to create crypto public key type integer: %v", err)
	}

	// Directly write the bytes of the Integer instances to the payload
	payload.Write(*signingPublicKeyType)
	payload.Write(*cryptoPublicKeyType)

	err = binary.Write(&payload, binary.BigEndian, signingPublicKeyType)
	if err != nil {
		t.Fatalf("Failed to write signing public key type to payload: %v\n", err)
	}

	err = binary.Write(&payload, binary.BigEndian, cryptoPublicKeyType)
	if err != nil {
		t.Fatalf("Failed to write crypto public key type to payload: %v\n", err)
	}

	// Create KeyCertificate specifying key types
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		t.Fatalf("Failed to create new certificate: %v\n", err)
	}

	certBytes := cert.Bytes()
	t.Logf("Serialized Certificate Size: %d bytes", len(certBytes))

	keyCert, err := key_certificate.KeyCertificateFromCertificate(*cert)
	if err != nil {
		log.Fatalf("KeyCertificateFromCertificate failed: %v\n", err)
	}
	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SignatureSize()
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	if err != nil {
		t.Fatalf("Failed to generate random padding: %v\n", err)
	}
	// Create RouterIdentity
	routerIdentity, err := router_identity.NewRouterIdentity(elg_pubkey, ed25519_pubkey, *cert, padding)
	if err != nil {
		t.Fatalf("Failed to create router identity: %v\n", err)
	}
	// create some dummy addresses
	options := map[string]string{}
	routerAddress, err := router_address.NewRouterAddress(3, <-time.After(1*time.Second), "NTCP2", options)
	if err != nil {
		t.Fatalf("Failed to create router address: %v\n", err)
	}
	routerAddresses := []*router_address.RouterAddress{routerAddress}
	// create router info
	routerInfo, err := NewRouterInfo(routerIdentity, time.Now(), routerAddresses, nil, &ed25519_privkey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	if err != nil {
		t.Fatalf("Failed to create router info: %v\n", err)
	}

	t.Run("Serialize and Deserialize RouterInfo", func(t *testing.T) {
		routerInfoBytes, err := routerInfo.Bytes()
		t.Log(len(routerInfoBytes), routerInfo.String(), routerInfoBytes)
		if err != nil {
			t.Fatalf("Failed to write RouterInfo to bytes: %v\n", err)
		}
		_, _, err = ReadRouterInfo(routerInfoBytes)
		if err != nil {
			t.Fatalf("Failed to read routerInfoBytes: %v\n", err)
		}
	})
}
