// Tests for router identity hash encoding. Validates that the router identity
// hash is encoded with the I2P base64 alphabet.
package router

import (
	"encoding/base64"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncodeRouterIdentityHash_UsesI2PBase64Alphabet verifies that the router identity
// hash is encoded with the I2P base64 alphabet, not standard base64.
func TestEncodeRouterIdentityHash_UsesI2PBase64Alphabet(t *testing.T) {
	const stdEncoded = "Z3H3W12TDR3zzEq0t7APhZH3qFFlH2YUN4oXPo/K3oE="

	rawHash, err := base64.StdEncoding.DecodeString(stdEncoded)
	require.NoError(t, err)
	require.Len(t, rawHash, len(common.Hash{}))

	var hash common.Hash
	copy(hash[:], rawHash)

	got := encodeRouterIdentityHash(hash)

	assert.Equal(t, "Z3H3W12TDR3zzEq0t7APhZH3qFFlH2YUN4oXPo~K3oE=", got)
	assert.NotContains(t, got, "/")
	assert.NotContains(t, got, "+")
}
