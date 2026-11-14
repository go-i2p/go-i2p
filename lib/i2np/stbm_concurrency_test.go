// GI-I2NP-001 regression: concurrent ShortTunnelBuild (type-25) processing must
// not corrupt or race on shared per-slot reply state.
//
// Before the fix, decryptShortRecord wrote the Noise-derived reply key into a
// map field shared across the whole MessageProcessor (p.stbmSlotCrypto), while
// encryptBuildReply read it back. ProcessMessage runs on transport AND
// inbound-tunnel goroutines, so two simultaneous type-25 messages performed
// concurrent map writes -> "fatal error: concurrent map writes" killed the
// router process. The fix threads a per-message map through the parse/reply
// chain, so no per-processor mutable state is shared.
//
// Run with -race to catch the data race; the goroutine fan-out also makes the
// fatal concurrent-map-write panic reproducible without -race.
package i2np

import (
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/require"
)

// newSelfEncryptableSTBM builds a one-record ShortTunnelBuild body that this
// router can actually decrypt: it generates an X25519 keypair, publishes it in a
// RouterInfo, encrypts a build record addressed to that identity, and returns the
// wire body plus the matching identity hash and private key. A record that fails
// to decrypt never reaches the reply-state write, so a real keypair is required
// to exercise the path the race lived on.
func newSelfEncryptableSTBM(t *testing.T) (body []byte, ourHash common.Hash, ourPriv []byte) {
	t.Helper()

	// X25519 encryption keypair (the recipient = us).
	encPub, encPriv, err := curve25519.GenerateKeyPair()
	require.NoError(t, err)
	receivingPub, ok := encPub.(types.ReceivingPublicKey)
	require.True(t, ok, "X25519 public key must implement ReceivingPublicKey")

	// Ed25519 signing keypair (required to build a valid KeysAndCert).
	signPriv, err := ed25519.GenerateEd25519Key()
	require.NoError(t, err)
	signPrivTyped, ok := signPriv.(ed25519.Ed25519PrivateKey)
	require.True(t, ok)
	signPub, err := signPrivTyped.Public()
	require.NoError(t, err)

	keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
	require.NoError(t, err)

	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	padding := make([]byte, keys_and_cert.KEYS_AND_CERT_DATA_SIZE-pubKeySize-sigKeySize)
	_, err = rand.Read(padding)
	require.NoError(t, err)

	kac, err := keys_and_cert.NewKeysAndCert(keyCert, receivingPub, padding, signPub.(types.SigningPublicKey))
	require.NoError(t, err)

	ident, err := router_identity.NewRouterIdentityFromKeysAndCert(kac)
	require.NoError(t, err)

	addr, err := router_address.NewRouterAddress(0, time.Now().Add(time.Hour), "NTCP2", map[string]string{})
	require.NoError(t, err)

	ri, err := router_info.NewRouterInfo(
		ident,
		time.Now(),
		[]*router_address.RouterAddress{addr},
		map[string]string{"netId": "0", "router.version": "0.9.67"},
		&signPrivTyped,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	hash, err := ri.IdentHash()
	require.NoError(t, err)

	record := createTestBuildRequestRecord(t)
	record.OurIdent = hash

	encrypted, err := EncryptShortBuildRequestRecord(record, *ri)
	require.NoError(t, err)

	// Wire body: [count:1][slot:218].
	body = make([]byte, 1+ShortBuildRecordSize)
	body[0] = 1
	copy(body[1:], encrypted[:])

	return body, hash, encPriv.Bytes()
}

// TestConcurrentShortTunnelBuildNoSharedReplyState drives many goroutines
// through the type-25 build path at once. Each message decrypts to us, so every
// goroutine writes its per-slot reply state; with the old shared map this is a
// concurrent map write (fatal) and a -race data race. With the per-message map
// the calls are independent and must all succeed.
func TestConcurrentShortTunnelBuildNoSharedReplyState(t *testing.T) {
	body, ourHash, ourPriv := newSelfEncryptableSTBM(t)

	processor := NewMessageProcessor()
	processor.SetOurRouterHash(ourHash)
	processor.SetOurPrivateKey(ourPriv)
	participants := newMockParticipantManager(true)
	processor.SetParticipantManager(participants)
	processor.SetBuildReplyForwarder(newMockBuildReplyForwarder())

	const goroutines = 64
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := NewBaseI2NPMessage(I2NPMessageTypeShortTunnelBuild)
			msg.SetData(body)
			if err := processor.processShortTunnelBuildMessage(msg); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err, "concurrent build processing must not fail")
	}

	// Every message must have decrypted to us and registered participation,
	// proving the per-slot reply-state write (the racing site) actually ran on
	// each goroutine rather than the test passing vacuously on undecryptable data.
	require.Equal(t, goroutines, participants.getRegisteredCount(),
		"all messages must decrypt and reach the reply-state write")
}
