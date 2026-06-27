package ssu2

import (
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type replayTestConn struct {
	remote net.Addr
}

func (c *replayTestConn) Read(_ []byte) (int, error)         { return 0, nil }
func (c *replayTestConn) Write(_ []byte) (int, error)        { return 0, nil }
func (c *replayTestConn) Close() error                       { return nil }
func (c *replayTestConn) LocalAddr() net.Addr                { return nil }
func (c *replayTestConn) RemoteAddr() net.Addr               { return c.remote }
func (c *replayTestConn) SetDeadline(_ time.Time) error      { return nil }
func (c *replayTestConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *replayTestConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestDeriveReplayProxyKey_DeterministicForSameConnection(t *testing.T) {
	underlying := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 8), Port: 12345}
	var routerHash data.Hash
	routerHash[0] = 0xAA
	addr, err := ssu2noise.NewSSU2Addr(underlying, routerHash, 0x1122334455667788, "responder")
	require.NoError(t, err)

	conn := &replayTestConn{remote: addr}
	key1 := deriveReplayProxyKey(conn)
	key2 := deriveReplayProxyKey(conn)

	assert.Equal(t, key1, key2, "replay proxy key must be stable for same connection metadata")
	assert.NotEqual(t, [32]byte{}, key1, "derived replay key must not be all-zero")
}

func TestDeriveReplayProxyKey_DifferentConnectionIDsYieldDifferentKeys(t *testing.T) {
	underlying := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 8), Port: 12345}
	var routerHash data.Hash
	routerHash[0] = 0xAA

	addr1, err := ssu2noise.NewSSU2Addr(underlying, routerHash, 0x1111111111111111, "responder")
	require.NoError(t, err)
	addr2, err := ssu2noise.NewSSU2Addr(underlying, routerHash, 0x2222222222222222, "responder")
	require.NoError(t, err)

	key1 := deriveReplayProxyKey(&replayTestConn{remote: addr1})
	key2 := deriveReplayProxyKey(&replayTestConn{remote: addr2})

	assert.NotEqual(t, key1, key2, "connection ID must contribute to replay key derivation")
}

func TestCheckConnectionReplay_DetectsRepeatForStableMetadata(t *testing.T) {
	handler := NewDefaultHandler()
	defer handler.Close()

	tx := &SSU2Transport{handler: handler}
	underlying := &net.UDPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 4444}
	var routerHash data.Hash
	routerHash[0] = 0x55
	addr, err := ssu2noise.NewSSU2Addr(underlying, routerHash, 0xAABBCCDDEEFF0011, "responder")
	require.NoError(t, err)
	conn := &replayTestConn{remote: addr}

	assert.False(t, tx.checkConnectionReplay(conn), "first observation should not be replay")
	assert.True(t, tx.checkConnectionReplay(conn), "second observation of same metadata should be replay")
}
