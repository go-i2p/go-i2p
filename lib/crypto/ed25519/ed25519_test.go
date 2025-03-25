package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
)

func TestEd25519(t *testing.T) {
	var pubKey Ed25519PublicKey

	signer := new(Ed25519Signer)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Log("Failed to generate ed25519 test key")
		t.Fail()
	}
	pubKey = []byte(pub)
	signer.k = []byte(priv)

	message := make([]byte, 123)
	io.ReadFull(rand.Reader, message)

	sig, err := signer.Sign(message)
	if err != nil {
		t.Log("Failed to sign message")
		t.Fail()
	}

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Logf("Error from verifier: %s", err)
		t.Fail()
	}

	err = verifier.Verify(message, sig)
	if err != nil {
		t.Log("Failed to verify message")
		t.Fail()
	}
}
