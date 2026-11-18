// Tests for the OutboundTunnelBuildReply wire format.
package i2np

import (
	"crypto/rand"
	"testing"

	i2ptunnel "github.com/go-i2p/crypto/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSTBMReplyRecordFormat verifies the ECIES/STBM short reply record format
// against the production AEAD primitive (crypto/tunnel.EncryptOwnBuildReply),
// per tunnel-creation-ecies.md §"Short Reply Record":
//   - 202-byte cleartext: 2-byte options + random padding + 1-byte ret code at 201
//   - 218-byte encrypted record, which INCLUDES the 16-byte Poly1305 tag
//     (202 ciphertext + 16 MAC = 218; the MAC is not added on top).
//
// This addresses audit gap C1 (TEST_SPEC_COMPLIANCE_ANALYSIS.md) and finding
// GI-E01: the previous version asserted a 234-byte total that double-counted the
// MAC and only compared locally-declared constants, so it tested no production
// code. A maintainer aligning the wire format to 234 would emit records no
// conforming 0.9.51+ router reads (wire slots are 218 bytes).
func TestSTBMReplyRecordFormat(t *testing.T) {
	var key, ad [32]byte
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	_, err = rand.Read(ad[:])
	require.NoError(t, err)

	// Valid ECIES short reply codes: accept and bandwidth-reject.
	validRetCodes := []byte{TunnelBuildReplySuccess, TunnelBuildReplyBandwidth}
	for _, ret := range validRetCodes {
		t.Run("ret_"+string(rune(ret)), func(t *testing.T) {
			// Cleartext layout (tunnel-creation-ecies.md §"Short Reply Record
			// Unencrypted"): bytes 0-1 = options, bytes 2-200 = random padding,
			// byte 201 = reply code.
			cleartext := make([]byte, ShortBuildReplyCleartextSize) // 202
			require.Equal(t, 202, len(cleartext))
			_, err := rand.Read(cleartext[2:ShortBuildReplyCodeOffset]) // padding
			require.NoError(t, err)
			cleartext[ShortBuildReplyCodeOffset] = ret // offset 201

			// Production AEAD seal. The encrypted short reply record is 218 bytes
			// total, MAC included (spec: "Encrypted size: 218 bytes").
			ciphertext, err := i2ptunnel.EncryptOwnBuildReply(key, ad, 0, cleartext)
			require.NoError(t, err)
			require.Len(t, ciphertext, ShortBuildRecordSize,
				"STBM encrypted reply must be 218 bytes total (202 ciphertext + 16 MAC, MAC included)")

			// Round-trip through the production open path and confirm the reply
			// code survives at offset 201.
			out, err := i2ptunnel.DecryptOwnBuildReply(key, ad, 0, ciphertext)
			require.NoError(t, err)
			require.Len(t, out, ShortBuildReplyCleartextSize)
			assert.Equal(t, ret, out[ShortBuildReplyCodeOffset],
				"reply byte must round-trip at position 201 (last byte of 202-byte cleartext)")
		})
	}
}

// TestSTBMReplyRecordAEADIntegrity verifies that the production AEAD path
// (crypto/tunnel.EncryptOwnBuildReply + decryptSTBMReplySlot) detects tampering
// in the 218-byte STBM reply record via the Poly1305 tag.
//
// This addresses finding GI-E02: the previous version used a test-local shim that
// appended zero MAC bytes and gated decryption on length, so the tamper assertion
// passed on length rather than on a real tag. It now drives the same primitive the
// reply handler uses (decryptSTBMReplySlot -> DecryptOwnBuildReply).
func TestSTBMReplyRecordAEADIntegrity(t *testing.T) {
	var key, ad [32]byte
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	_, err = rand.Read(ad[:])
	require.NoError(t, err)

	cleartext := make([]byte, ShortBuildReplyCleartextSize) // 202
	_, err = rand.Read(cleartext[2:ShortBuildReplyCodeOffset])
	require.NoError(t, err)
	cleartext[ShortBuildReplyCodeOffset] = TunnelBuildReplySuccess

	ciphertext, err := i2ptunnel.EncryptOwnBuildReply(key, ad, 0, cleartext)
	require.NoError(t, err)
	require.Len(t, ciphertext, ShortBuildRecordSize,
		"STBM encrypted reply must be 218 bytes (202 ciphertext + 16 MAC, per spec)")

	// Sanity: the untouched record opens cleanly through the production slot path.
	out, err := decryptSTBMReplySlot(ciphertext, key, ad, 0)
	require.NoError(t, err)
	require.Len(t, out, ShortBuildReplyCleartextSize)
	assert.Equal(t, byte(TunnelBuildReplySuccess), out[ShortBuildReplyCodeOffset])

	// Tamper with a ciphertext byte: the Poly1305 tag must reject it.
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[50] ^= 0x01

	_, err = decryptSTBMReplySlot(tampered, key, ad, 0)
	assert.Error(t, err, "tampered STBM reply ciphertext must fail AEAD tag verification")

	// A truncated record must also fail (size gate), not silently parse.
	_, err = decryptSTBMReplySlot(ciphertext[:ShortBuildRecordSize-1], key, ad, 0)
	assert.Error(t, err, "truncated STBM reply record must fail AEAD verification")
}
