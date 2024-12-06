package crypto

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"testing"

	"golang.org/x/crypto/openpgp/elgamal"
)

func BenchmarkElgGenerate(b *testing.B) {
	k := new(elgamal.PrivateKey)
	for n := 0; n < b.N; n++ {
		err := ElgamalGenerate(k, rand.Reader)
		if err != nil {
			panic(err.Error())
		}
	}
}

func BenchmarkElgDecrypt(b *testing.B) {
	prv := new(elgamal.PrivateKey)
	err := ElgamalGenerate(prv, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	pub := createElgamalPublicKey(prv.Y.Bytes())
	enc, err := createElgamalEncryption(pub, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	d := make([]byte, 222)
	_, _ = io.ReadFull(rand.Reader, d)
	c, err := enc.Encrypt(d)
	fails := 0
	dec := &elgDecrypter{
		k: prv,
	}
	for n := 0; n < b.N; n++ {
		p, err := dec.Decrypt(c)
		if err != nil {
			fails++
		} else if !bytes.Equal(p, d) {
			fails++
		}
	}
	log.Debugf("%d fails %d rounds", fails, b.N)
}

func BenchmarkElgEncrypt(b *testing.B) {
	prv := new(elgamal.PrivateKey)
	err := ElgamalGenerate(prv, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	pub := createElgamalPublicKey(prv.Y.Bytes())
	enc, err := createElgamalEncryption(pub, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	d := make([]byte, 222)
	_, err = io.ReadFull(rand.Reader, d)
	fails := 0
	for n := 0; n < b.N; n++ {
		_, err := enc.Encrypt(d)
		if err != nil {
			fails++
		}
	}
	log.Debugf("%d fails %d rounds", fails, b.N)
}

func TestElg(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err == nil {
		msg := make([]byte, 222)
		_, err := io.ReadFull(rand.Reader, msg)
		if err == nil {
			pub := createElgamalPublicKey(k.Y.Bytes())
			enc, err := createElgamalEncryption(pub, rand.Reader)
			if err == nil {
				emsg, err := enc.Encrypt(msg)
				if err == nil {
					dec, err := elgamalDecrypt(k, emsg, true)
					if err == nil {
						if bytes.Equal(dec, msg) {
							t.Logf("%q == %q", dec, msg)
						} else {
							t.Logf("%q != %q", dec, msg)
							t.Fail()
						}
					} else {
						t.Logf("decrypt failed: %s", err.Error())
						t.Fail()
					}
				} else {
					t.Logf("failed to encrypt message: %s", err.Error())
					t.Fail()
				}
			} else {
				t.Logf("failed to create encryption: %s", err.Error())
				t.Fail()
			}
		} else {
			t.Logf("failed to generate random message: %s", err.Error())
			t.Fail()
		}
	} else {
		t.Logf("error while generating key: %s", err.Error())
		t.Fail()
	}
}

// Test key generation and properties
func TestElgKeyGeneration(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal key: %v", err)
	}

	if k.P.Cmp(elgp) != 0 {
		t.Error("Generated key has incorrect P value")
	}
	if k.G.Cmp(elgg) != 0 {
		t.Error("Generated key has incorrect G value")
	}
	if k.Y == nil {
		t.Error("Public component Y is nil")
	}
	if k.X == nil {
		t.Error("Private component X is nil")
	}

	expectedY := new(big.Int).Exp(k.G, k.X, k.P)
	if k.Y.Cmp(expectedY) != 0 {
		t.Error("Public component Y doesn't match G^X mod P")
	}
}

// Test public key operations
func TestElgPublicKey(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal key: %v", err)
	}

	pubKey := createElgamalPublicKey(k.Y.Bytes())
	if pubKey == nil {
		t.Fatal("Failed to create public key")
	}

	if pubKey.P.Cmp(elgp) != 0 {
		t.Error("Public key has wrong P value")
	}
	if pubKey.G.Cmp(elgg) != 0 {
		t.Error("Public key has wrong G value")
	}
	if pubKey.Y.Cmp(k.Y) != 0 {
		t.Error("Public key has wrong Y value")
	}

	invalidPub := createElgamalPublicKey(make([]byte, 128))
	if invalidPub != nil {
		t.Error("Expected nil for invalid public key creation")
	}
}

// Test private key operations
func TestElgPrivateKey(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal key: %v", err)
	}

	privKey := createElgamalPrivateKey(k.X.Bytes())
	if privKey == nil {
		t.Fatal("Failed to create private key")
	}

	if privKey.P.Cmp(elgp) != 0 {
		t.Error("Private key has wrong P value")
	}
	if privKey.G.Cmp(elgg) != 0 {
		t.Error("Private key has wrong G value")
	}
	if privKey.X.Cmp(k.X) != 0 {
		t.Error("Private key has wrong X value")
	}
	if privKey.Y.Cmp(k.Y) != 0 {
		t.Error("Private key has wrong Y value")
	}

	invalidPriv := createElgamalPrivateKey(make([]byte, 128))
	if invalidPriv != nil {
		t.Error("Expected nil for invalid private key creation")
	}
}

// Test encryption session creation
func TestElgEncryptionSession(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal key: %v", err)
	}

	pub := createElgamalPublicKey(k.Y.Bytes())
	enc, err := createElgamalEncryption(pub, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create encryption session: %v", err)
	}

	if enc.p.Cmp(pub.P) != 0 {
		t.Error("Encryption session has wrong P value")
	}
	if enc.a == nil {
		t.Error("Encryption session has nil A value")
	}
	if enc.b1 == nil {
		t.Error("Encryption session has nil B1 value")
	}

	tempKey := new(big.Int).Exp(enc.a, k.X, enc.p)
	tempKey = tempKey.ModInverse(tempKey, enc.p)
	result := new(big.Int).Mul(enc.b1, tempKey)
	result.Mod(result, enc.p)
	if result.Cmp(one) != 0 {
		t.Error("Encryption session parameters don't satisfy ElGamal properties")
	}
}

// Test encryption integrity
func TestElgEncryptionIntegrity(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal key: %v", err)
	}

	pub := createElgamalPublicKey(k.Y.Bytes())
	enc, err := createElgamalEncryption(pub, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create encryption: %v", err)
	}

	data := []byte("test message")
	encrypted, err := enc.Encrypt(data)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	tamperedData := make([]byte, len(encrypted))
	copy(tamperedData, encrypted)
	tamperedData[len(tamperedData)-1] ^= 0xFF

	decrypted, err := elgamalDecrypt(k, tamperedData, true)
	if err == nil {
		t.Error("Expected decryption of tampered data to fail")
	}
	if decrypted != nil {
		t.Error("Expected nil decrypted data for tampered input")
	}
}

func TestElgamalConcurrentOperations(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pub := createElgamalPublicKey(k.Y.Bytes())
	enc, err := createElgamalEncryption(pub, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create encryption: %v", err)
	}

	t.Run("Concurrent Encryptions", func(t *testing.T) {
		const numGoroutines = 50
		errChan := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				msg := make([]byte, 100)
				_, err := io.ReadFull(rand.Reader, msg)
				if err != nil {
					errChan <- fmt.Errorf("failed to generate random data: %v", err)
					return
				}

				_, err = enc.Encrypt(msg)
				errChan <- err
			}()
		}

		for i := 0; i < numGoroutines; i++ {
			if err := <-errChan; err != nil {
				t.Errorf("Concurrent encryption failed: %v", err)
			}
		}
	})
}

// Test key generation and properties
func TestElgKeyGenerationEncrypterInterface(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal key: %v", err)
	}

	if k.P.Cmp(elgp) != 0 {
		t.Error("Generated key has incorrect P value")
	}
	if k.G.Cmp(elgg) != 0 {
		t.Error("Generated key has incorrect G value")
	}
	if k.Y == nil {
		t.Error("Public component Y is nil")
	}
	if k.X == nil {
		t.Error("Private component X is nil")
	}

	expectedY := new(big.Int).Exp(k.G, k.X, k.P)
	if k.Y.Cmp(expectedY) != 0 {
		t.Error("Public component Y doesn't match G^X mod P")
	}
}

// Test public key operations
func TestElgPublicKeyEncrypterInterface(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal key: %v", err)
	}

	pubKey := ElgPublicKey{}
	copy(pubKey[:], k.Y.Bytes())

	encrypter, err := pubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create encrypter: %v", err)
	}

	// Perform type assertion to access *ElgamalEncryption fields
	encryptionSession, ok := encrypter.(*ElgamalEncryption)
	if !ok {
		t.Fatalf("Failed to assert Encrypter to *ElgamalEncryption")
	}

	if encryptionSession.p.Cmp(elgp) != 0 {
		t.Error("Encryption session has wrong P value")
	}
	if encryptionSession.a == nil {
		t.Error("Encryption session has nil A value")
	}
	if encryptionSession.b1 == nil {
		t.Error("Encryption session has nil B1 value")
	}
}

// Test private key operations
func TestElgPrivateKeyDecrypterInterface(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal key: %v", err)
	}

	privKey := ElgPrivateKey{}
	copy(privKey[:], k.X.Bytes())

	dec, err := privKey.NewDecrypter()
	if err != nil {
		t.Fatalf("Failed to create decrypter: %v", err)
	}

	decrypter, ok := dec.(*elgDecrypter)
	if !ok {
		t.Fatalf("Failed to assert Decrypter to *elgDecrypter")
	}

	if decrypter.k.P.Cmp(elgp) != 0 {
		t.Error("Private key has wrong P value")
	}
	if decrypter.k.G.Cmp(elgg) != 0 {
		t.Error("Private key has wrong G value")
	}
	if decrypter.k.X.Cmp(k.X) != 0 {
		t.Error("Private key has wrong X value")
	}
	if decrypter.k.Y.Cmp(k.Y) != 0 {
		t.Error("Private key has wrong Y value")
	}
}

// Test encryption session creation
func TestElgEncryptionSessionEncrypterInterface(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal key: %v", err)
	}

	pubKey := ElgPublicKey{}
	copy(pubKey[:], k.Y.Bytes())

	enc, err := pubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create encryption session: %v", err)
	}

	// Perform type assertion to access *ElgamalEncryption fields
	encryptionSession, ok := enc.(*ElgamalEncryption)
	if !ok {
		t.Fatalf("Failed to assert Encrypter to *ElgamalEncryption")
	}

	if encryptionSession.p.Cmp(elgp) != 0 {
		t.Error("Encryption session has wrong P value")
	}
	if encryptionSession.a == nil {
		t.Error("Encryption session has nil A value")
	}
	if encryptionSession.b1 == nil {
		t.Error("Encryption session has nil B1 value")
	}

	tempKey := new(big.Int).Exp(encryptionSession.a, k.X, encryptionSession.p)
	tempKey = tempKey.ModInverse(tempKey, encryptionSession.p)
	result := new(big.Int).Mul(encryptionSession.b1, tempKey)
	result.Mod(result, encryptionSession.p)
	if result.Cmp(one) != 0 {
		t.Error("Encryption session parameters don't satisfy ElGamal properties")
	}
}

// Test encryption integrity
func TestElgEncryptionIntegrityEncrypterInterface(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal key: %v", err)
	}

	pubKey := ElgPublicKey{}
	copy(pubKey[:], k.Y.Bytes())

	enc, err := pubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create encryption session: %v", err)
	}

	data := []byte("test message")
	encrypted, err := enc.Encrypt(data)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	tamperedData := make([]byte, len(encrypted))
	copy(tamperedData, encrypted)
	tamperedData[len(tamperedData)-1] ^= 0xFF

	decrypted, err := elgamalDecrypt(k, tamperedData, true)
	if err == nil {
		t.Error("Expected decryption of tampered data to fail")
	}
	if decrypted != nil {
		t.Error("Expected nil decrypted data for tampered input")
	}
}

func TestElgamalConcurrentOperationsEncrypterInterface(t *testing.T) {
	k := new(elgamal.PrivateKey)
	err := ElgamalGenerate(k, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pubKey := ElgPublicKey{}
	copy(pubKey[:], k.Y.Bytes())

	enc, err := pubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create encryption session: %v", err)
	}

	t.Run("Concurrent Encryptions", func(t *testing.T) {
		const numGoroutines = 50
		errChan := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				msg := make([]byte, 100)
				_, err := io.ReadFull(rand.Reader, msg)
				if err != nil {
					errChan <- fmt.Errorf("failed to generate random data: %v", err)
					return
				}

				_, err = enc.Encrypt(msg)
				errChan <- err
			}()
		}

		for i := 0; i < numGoroutines; i++ {
			if err := <-errChan; err != nil {
				t.Errorf("Concurrent encryption failed: %v", err)
			}
		}
	})
}
