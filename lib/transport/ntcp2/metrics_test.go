package ntcp2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransportMetricsHandshakePhaseFailureCounters(t *testing.T) {
	transport := newNilListenerTestTransport(t, 4)

	transport.recordTCPDialFailure()
	transport.recordTCPDialFailure()
	transport.recordNoiseHandshakeFailure()
	transport.recordNoiseHandshakeFailure()
	transport.recordNoiseHandshakeFailure()

	metrics := transport.GetTransportMetrics()
	require.Equal(t, uint64(2), metrics.TCPDialFailures)
	require.Equal(t, uint64(3), metrics.NoiseHandshakeFailures)
}
