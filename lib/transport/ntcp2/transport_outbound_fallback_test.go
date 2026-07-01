package ntcp2

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	noise "github.com/go-i2p/go-noise/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeWrappedAddr(t *testing.T, hostPort string, marker byte) net.Addr {
	t.Helper()
	host, port, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	require.NoError(t, err)

	var h data.Hash
	for i := range h {
		h[i] = marker
	}

	addr, err := noise.NewNTCP2Addr(tcpAddr, h, "initiator")
	require.NoError(t, err)
	return addr
}

func TestTryDialCandidates_AttemptsUntilSuccess(t *testing.T) {
	transport, cancel := newMinimalTransport()
	defer cancel()

	addrs := []net.Addr{
		makeWrappedAddr(t, "127.0.0.1:11001", 1),
		makeWrappedAddr(t, "127.0.0.1:11002", 2),
	}

	attempted := make([]string, 0, 2)
	failErr := errors.New("first failed")

	perform := func(addr net.Addr, tcpAddrString string, _ []byte, _ *noise.Config, _ time.Time) (*noise.Conn, error) {
		attempted = append(attempted, tcpAddrString)
		if len(attempted) == 1 {
			return nil, failErr
		}
		return &noise.Conn{}, nil
	}

	peerHashBytes := make([]byte, 32)
	config := &noise.Config{}

	conn, err := dialCandidatesWithPerformer(transport, addrs, peerHashBytes, config, perform)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, []string{"127.0.0.1:11001", "127.0.0.1:11002"}, attempted)
}

func TestTryDialCandidates_AllFailReturnsLastError(t *testing.T) {
	transport, cancel := newMinimalTransport()
	defer cancel()

	addrs := []net.Addr{
		makeWrappedAddr(t, "127.0.0.1:12001", 3),
		makeWrappedAddr(t, "127.0.0.1:12002", 4),
	}

	firstErr := errors.New("first")
	lastErr := errors.New("last")
	attempted := make([]string, 0, 2)

	perform := func(addr net.Addr, tcpAddrString string, _ []byte, _ *noise.Config, _ time.Time) (*noise.Conn, error) {
		attempted = append(attempted, tcpAddrString)
		if len(attempted) == 1 {
			return nil, firstErr
		}
		return nil, lastErr
	}

	peerHashBytes := make([]byte, 32)
	config := &noise.Config{}

	conn, err := dialCandidatesWithPerformer(transport, addrs, peerHashBytes, config, perform)
	assert.Nil(t, conn)
	require.Error(t, err)
	assert.ErrorIs(t, err, lastErr)
	assert.Equal(t, []string{"127.0.0.1:12001", "127.0.0.1:12002"}, attempted)
}
