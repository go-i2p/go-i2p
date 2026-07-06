package ntcp2

import (
	"bytes"
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

func TestAttachDateTimeMetadataIfDue_PrependsDateTimeBlock(t *testing.T) {
	session := &NTCP2Session{}
	framedData := []byte{0xAA, 0xBB, 0xCC}
	metaPrefix := SerializeBlocks(NewDateTimeBlock())
	nextMetaAt := time.Now().Add(-1 * time.Second)

	result := session.attachDateTimeMetadataIfDue(framedData, &nextMetaAt)

	require.GreaterOrEqual(t, nextMetaAt, time.Now().Add(-1*time.Second))
	require.True(t, bytes.HasPrefix(result, metaPrefix))
	require.Equal(t, framedData, result[len(metaPrefix):])
}

func TestAttachDateTimeMetadataIfDue_NotDueLeavesFrameUnchanged(t *testing.T) {
	session := &NTCP2Session{}
	framedData := []byte{0x11, 0x22, 0x33}
	nextMetaAt := time.Now().Add(10 * time.Minute)
	originalNextMetaAt := nextMetaAt

	result := session.attachDateTimeMetadataIfDue(framedData, &nextMetaAt)

	require.Equal(t, framedData, result)
	require.Equal(t, originalNextMetaAt, nextMetaAt)
}
