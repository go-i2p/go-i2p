package ntcp2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNextMetaIntervalWithRand_JavaI2PRange(t *testing.T) {
	half := ntcp2MetaFrequency / 2

	min := nextMetaIntervalWithRand(func(_ int64) int64 { return 0 })
	require.Equal(t, half, min)

	max := nextMetaIntervalWithRand(func(n int64) int64 { return n - 1 })
	require.Equal(t, ntcp2MetaFrequency-time.Nanosecond, max)

	mid := nextMetaIntervalWithRand(func(n int64) int64 { return n / 2 })
	require.GreaterOrEqual(t, mid, half)
	require.Less(t, mid, ntcp2MetaFrequency)
}
