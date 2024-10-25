package noise

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/go-i2p/go-i2p/lib/crypto"
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
func TestEncryptDecryptPacketObfsOffline(t *testing.T) {
	// Simulate Bob's Router Hash (RH_B)
	bobRouterHash := make([]byte, 32)
	rand.Read(bobRouterHash)

	// Simulate Bob's IV (ri.IV)
	bobIV := make([]byte, 16)
	rand.Read(bobIV)

	// Create AES cipher block
	aesBlock, err := aes.NewCipher(bobRouterHash)
	if err != nil {
		t.Fatalf("Failed to create AES cipher block: %v", err)
	}

	// Create AES CBC encrypter and decrypter
	aesEncrypter := cipher.NewCBCEncrypter(aesBlock, bobIV)
	aesDecrypter := cipher.NewCBCDecrypter(aesBlock, bobIV)

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

	// Alice's Handshake State
	initiatorHS, err := noise.NewHandshakeState(noise.Config{
		StaticKeypair: initiatorStatic,
		Initiator:     true,
		Pattern:       pattern,
		CipherSuite:   cipherSuite,
		Prologue:      prologue,
		PeerStatic:    responderStatic.Public, // Bob's static public key
	})
	if err != nil {
		t.Fatalf("Failed to create initiator handshake state: %v", err)
	}

	// Bob's Handshake State
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

	// -------------------------------
	// Message 1: Initiator -> Responder
	// -------------------------------

	// Alice writes message 1
	msg1, cs0, cs1, err := initiatorHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Initiator failed to write handshake message 1: %v", err)
	}
	if cs0 != nil || cs1 != nil {
		t.Fatalf("Initiator should not have CipherStates after message 1")
	}

	// Encrypt Alice's ephemeral public key using AES-256-CBC
	if len(msg1) < 32 {
		t.Fatalf("Message 1 is too short to contain ephemeral public key")
	}
	aliceEphemeralPubKey := msg1[:32] // First 32 bytes
	encryptedX := make([]byte, len(aliceEphemeralPubKey))
	aesEncrypter.CryptBlocks(encryptedX, aliceEphemeralPubKey)

	// Construct the modified message 1
	fullMsg1 := append(encryptedX, msg1[32:]...)

	// -------------------------------
	// Responder processes message 1
	// -------------------------------

	// Extract encrypted ephemeral public key
	encryptedXReceived := fullMsg1[:32]
	// Decrypt the ephemeral public key
	decryptedX := make([]byte, len(encryptedXReceived))
	aesDecrypter.CryptBlocks(decryptedX, encryptedXReceived)

	// Replace the encrypted ephemeral key with the decrypted one
	modifiedMsg1 := append(decryptedX, fullMsg1[32:]...)

	// Bob reads message 1
	_, cs0, cs1, err = responderHS.ReadMessage(nil, modifiedMsg1)
	if err != nil {
		t.Fatalf("Responder failed to read handshake message 1: %v", err)
	}
	if cs0 != nil || cs1 != nil {
		t.Fatalf("Responder should not have CipherStates after reading message 1")
	}

	// -------------------------------
	// Message 2: Responder -> Initiator
	// -------------------------------

	// Bob writes message 2
	msg2, cs0, cs1, err := responderHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Responder failed to write handshake message 2: %v", err)
	}
	if cs0 != nil || cs1 != nil {
		t.Fatalf("Responder should not have CipherStates after writing message 2")
	}

	// Encrypt Bob's ephemeral public key using AES-256-CBC
	if len(msg2) < 32 {
		t.Fatalf("Message 2 is too short to contain ephemeral public key")
	}
	bobEphemeralPubKey := msg2[:32] // First 32 bytes
	encryptedY := make([]byte, len(bobEphemeralPubKey))
	aesEncrypter.CryptBlocks(encryptedY, bobEphemeralPubKey)

	// Construct the modified message 2
	fullMsg2 := append(encryptedY, msg2[32:]...)

	// -------------------------------
	// Initiator processes message 2
	// -------------------------------

	// Extract encrypted ephemeral public key
	encryptedYReceived := fullMsg2[:32]
	// Decrypt the ephemeral public key
	decryptedY := make([]byte, len(encryptedYReceived))
	aesDecrypter.CryptBlocks(decryptedY, encryptedYReceived)

	// Replace the encrypted ephemeral key with the decrypted one
	modifiedMsg2 := append(decryptedY, fullMsg2[32:]...)

	// Alice reads message 2
	_, cs0, cs1, err = initiatorHS.ReadMessage(nil, modifiedMsg2)
	if err != nil {
		t.Fatalf("Initiator failed to read handshake message 2: %v", err)
	}
	if cs0 != nil || cs1 != nil {
		t.Fatalf("Initiator should not have CipherStates after reading message 2")
	}

	// -------------------------------
	// Message 3: Initiator -> Responder
	// -------------------------------

	// Alice writes message 3
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

// ObfuscateEphemeralKey encrypts the ephemeral public key in the message using AES-256-CBC without padding
func ObfuscateEphemeralKey(message []byte, aesKey *crypto.AESSymmetricKey) ([]byte, error) {
	if len(message) < 32 {
		return nil, fmt.Errorf("message is too short to contain ephemeral public key")
	}

	// Extract the ephemeral public key (first 32 bytes)
	ephemeralPubKey := message[:32]

	// Create AES encrypter
	encrypter := &crypto.AESSymmetricEncrypter{
		Key: aesKey.Key,
		IV:  aesKey.IV,
	}

	// Encrypt the ephemeral public key without padding
	encryptedKey, err := encrypter.EncryptNoPadding(ephemeralPubKey)
	if err != nil {
		return nil, err
	}

	// Replace the ephemeral public key in the message with the encrypted key
	obfuscatedMessage := append(encryptedKey, message[32:]...)

	return obfuscatedMessage, nil
}

// DeobfuscateEphemeralKey decrypts the ephemeral public key in the message using AES-256-CBC without padding
func DeobfuscateEphemeralKey(message []byte, aesKey *crypto.AESSymmetricKey) ([]byte, error) {
	if len(message) < 32 {
		return nil, fmt.Errorf("message is too short to contain ephemeral public key")
	}

	// Extract the encrypted ephemeral public key (first 32 bytes)
	encryptedKey := message[:32]

	// Create AES decrypter
	decrypter := &crypto.AESSymmetricDecrypter{
		Key: aesKey.Key,
		IV:  aesKey.IV,
	}

	// Decrypt the ephemeral public key without padding
	decryptedKey, err := decrypter.DecryptNoPadding(encryptedKey)
	if err != nil {
		return nil, err
	}

	// Replace the encrypted ephemeral key in the message with the decrypted key
	deobfuscatedMessage := append(decryptedKey, message[32:]...)

	return deobfuscatedMessage, nil
}

// TestEncryptDecryptPacketObfsOffline tests the encryption and decryption with AES obfuscation
func TestEncryptDecryptPacketObfsOfflineWithFunc(t *testing.T) {
	// Simulate Bob's Router Hash (RH_B)
	bobRouterHash := make([]byte, 32)
	rand.Read(bobRouterHash)

	// Simulate Bob's IV (ri.IV)
	bobIV := make([]byte, 16)
	rand.Read(bobIV)

	// Create AES symmetric key
	aesKey := &crypto.AESSymmetricKey{
		Key: bobRouterHash,
		IV:  bobIV,
	}

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
	prologue := make([]byte, 2+len(negData))
	binary.BigEndian.PutUint16(prologue, uint16(len(negData)))
	copy(prologue[2:], negData)

	// Alice's Handshake State
	initiatorHS, err := noise.NewHandshakeState(noise.Config{
		StaticKeypair: initiatorStatic,
		Initiator:     true,
		Pattern:       pattern,
		CipherSuite:   cipherSuite,
		Prologue:      prologue,
		PeerStatic:    responderStatic.Public, // Bob's static public key
	})
	if err != nil {
		t.Fatalf("Failed to create initiator handshake state: %v", err)
	}

	// Bob's Handshake State
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

	// -------------------------------
	// Message 1: Initiator -> Responder
	// -------------------------------

	// Alice writes message 1
	msg1, cs0, cs1, err := initiatorHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Initiator failed to write handshake message 1: %v", err)
	}
	if cs0 != nil || cs1 != nil {
		t.Fatalf("Initiator should not have CipherStates after message 1")
	}

	// Obfuscate Alice's ephemeral public key in message 1
	obfuscatedMsg1, err := ObfuscateEphemeralKey(msg1, aesKey)
	if err != nil {
		t.Fatalf("Failed to obfuscate message 1: %v", err)
	}

	// -------------------------------
	// Responder processes message 1
	// -------------------------------

	// Deobfuscate Alice's ephemeral public key in message 1
	deobfuscatedMsg1, err := DeobfuscateEphemeralKey(obfuscatedMsg1, aesKey)
	if err != nil {
		t.Fatalf("Failed to deobfuscate message 1: %v", err)
	}

	// Bob reads message 1
	_, cs0, cs1, err = responderHS.ReadMessage(nil, deobfuscatedMsg1)
	if err != nil {
		t.Fatalf("Responder failed to read handshake message 1: %v", err)
	}
	if cs0 != nil || cs1 != nil {
		t.Fatalf("Responder should not have CipherStates after reading message 1")
	}

	// -------------------------------
	// Message 2: Responder -> Initiator
	// -------------------------------

	// Bob writes message 2
	msg2, cs0, cs1, err := responderHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Responder failed to write handshake message 2: %v", err)
	}
	if cs0 != nil || cs1 != nil {
		t.Fatalf("Responder should not have CipherStates after writing message 2")
	}

	// Obfuscate Bob's ephemeral public key in message 2
	obfuscatedMsg2, err := ObfuscateEphemeralKey(msg2, aesKey)
	if err != nil {
		t.Fatalf("Failed to obfuscate message 2: %v", err)
	}

	// -------------------------------
	// Initiator processes message 2
	// -------------------------------

	// Deobfuscate Bob's ephemeral public key in message 2
	deobfuscatedMsg2, err := DeobfuscateEphemeralKey(obfuscatedMsg2, aesKey)
	if err != nil {
		t.Fatalf("Failed to deobfuscate message 2: %v", err)
	}

	// Alice reads message 2
	_, cs0, cs1, err = initiatorHS.ReadMessage(nil, deobfuscatedMsg2)
	if err != nil {
		t.Fatalf("Initiator failed to read handshake message 2: %v", err)
	}
	if cs0 != nil || cs1 != nil {
		t.Fatalf("Initiator should not have CipherStates after reading message 2")
	}

	// -------------------------------
	// Message 3: Initiator -> Responder
	// -------------------------------

	// Alice writes message 3
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
	_, encryptedPacket, err := initiatorSession.encryptPacketDeux(originalData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	_, decryptedData, err := responderSession.decryptPacketDeux(encryptedPacket)
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
	_, encryptedResponse, err := responderSession.encryptPacketDeux(responseData)
	if err != nil {
		t.Fatalf("Responder encryption failed: %v", err)
	}

	_, decryptedResponse, err := initiatorSession.decryptPacketDeux(encryptedResponse)
	if err != nil {
		t.Fatalf("Initiator decryption failed: %v", err)
	}

	assert.Equal(t, responseData, decryptedResponse, "Decrypted response does not match original data")
}
