package router

import (
	"encoding/base64"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
