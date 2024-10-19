package noise

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/assert"
)

func TestEncryptDecryptPacketOffline(t *testing.T) {
	// Generate static keypairs
	initiatorStatic, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate initiator static keypair: %v", err)
	}
	responderStatic, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate responder static keypair: %v", err)
	}

	pattern := noise.HandshakeXK
	cipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	// Negotiation
	negData := initNegotiationData(nil)
	prologue := make([]byte, 2, uint16Size+len(negData))
	binary.BigEndian.PutUint16(prologue, uint16(len(negData)))
	prologue = append(prologue, negData...)

	// Handshake
	initiatorHS, err := noise.NewHandshakeState(noise.Config{
		StaticKeypair: initiatorStatic,
		Initiator:     true,
		Pattern:       pattern,
		CipherSuite:   cipherSuite,
		Prologue:      prologue,
		PeerStatic:    responderStatic.Public, // Must set this
	})
	if err != nil {
		t.Fatalf("Failed to create initiator handshake state: %v", err)
	}

	responderHS, err := noise.NewHandshakeState(noise.Config{
		StaticKeypair: responderStatic,
		Initiator:     false,
		Pattern:       pattern,
		CipherSuite:   cipherSuite,
		Prologue:      prologue,
	})
	if err != nil {
		t.Fatalf("Failed to create responder handshake state: %v", err)
	}

	var (
		initiatorSendCS *noise.CipherState
		initiatorRecvCS *noise.CipherState
		responderSendCS *noise.CipherState
		responderRecvCS *noise.CipherState
	)

	// Simulate the handshake message exchange

	// Message 1: Initiator -> Responder
	msg1, cs0, cs1, err := initiatorHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Initiator failed to write handshake message 1: %v", err)
	}
	if cs0 != nil || cs1 != nil {
		t.Fatalf("Initiator should not have CipherStates after message 1")
	}

	// Responder processes message 1
	_, cs0, cs1, err = responderHS.ReadMessage(nil, msg1)
	if err != nil {
		t.Fatalf("Responder failed to read handshake message 1: %v", err)
	}
	if cs0 != nil || cs1 != nil {
		t.Fatalf("Responder should not have CipherStates after reading message 1")
	}

	// Responder writes message 2
	msg2, cs0, cs1, err := responderHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Responder failed to write handshake message 2: %v", err)
	}
	if cs0 != nil || cs1 != nil {
		t.Fatalf("Responder should not have CipherStates after writing message 2")
	}

	// Initiator processes message 2
	_, cs0, cs1, err = initiatorHS.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("Initiator failed to read handshake message 2: %v", err)
	}
	if cs0 != nil || cs1 != nil {
		t.Fatalf("Initiator should not have CipherStates after reading message 2")
	}

	// Initiator writes message 3
	msg3, cs0, cs1, err := initiatorHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Initiator failed to write handshake message 3: %v", err)
	}
	if cs0 == nil || cs1 == nil {
		t.Fatalf("Initiator did not receive CipherStates after writing message 3")
	}
	initiatorSendCS = cs0
	initiatorRecvCS = cs1

	// Responder processes message 3
	_, cs0, cs1, err = responderHS.ReadMessage(nil, msg3)
	if err != nil {
		t.Fatalf("Responder failed to read handshake message 3: %v", err)
	}
	if cs0 == nil || cs1 == nil {
		t.Fatalf("Responder did not receive CipherStates after reading message 3")
	}
	responderRecvCS = cs0
	responderSendCS = cs1

	// Now both parties have the CipherStates

	// Initiator sends a message to Responder
	initiatorSession := &NoiseSession{
		CipherState: initiatorSendCS,
	}
	responderSession := &NoiseSession{
		CipherState: responderRecvCS,
	}

	originalData := []byte("This is a test message.")
	_, encryptedPacket, err := initiatorSession.encryptPacket(originalData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	_, decryptedData, err := responderSession.decryptPacket(encryptedPacket[2:])
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	assert.Equal(t, originalData, decryptedData, "Decrypted data does not match the original data")

	// Responder sends a message to Initiator
	responderSession = &NoiseSession{
		CipherState: responderSendCS,
	}
	initiatorSession = &NoiseSession{
		CipherState: initiatorRecvCS,
	}

	responseData := []byte("This is a response message.")
	_, encryptedResponse, err := responderSession.encryptPacket(responseData)
	if err != nil {
		t.Fatalf("Responder encryption failed: %v", err)
	}

	_, decryptedResponse, err := initiatorSession.decryptPacket(encryptedResponse[2:])
	if err != nil {
		t.Fatalf("Initiator decryption failed: %v", err)
	}

	assert.Equal(t, responseData, decryptedResponse, "Decrypted response does not match original data")
}
