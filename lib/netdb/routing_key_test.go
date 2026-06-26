package netdb

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRoutingKey_KnownVector verifies our RoutingKey implementation against the
// vector provided by zzz on 2026-06-25 (I2P #forum / IRC):
//
//	Input hash:   rwTXYqyGQTsvwcz8eM3CFxP8KvBU3tX95bAOTyxGTcI=
//	Date:         20260626
//	Routing key:  vc4-qqPqRlgybuqknKxCJXjMrn8Y-qBvZN4aeRG0ltw=   (I2P base64url)
//
// I2P uses base64url (RFC 4648 §5, - and _ instead of + and /) without padding.
// Our SHA256 computation uses standard base64 internally; we compare the raw bytes.
func TestRoutingKey_KnownVector(t *testing.T) {
	// Input hash in standard base64
	rawHash, err := base64.StdEncoding.DecodeString("rwTXYqyGQTsvwcz8eM3CFxP8KvBU3tX95bAOTyxGTcI=")
	require.NoError(t, err, "base64 decode of input hash")
	require.Len(t, rawHash, 32)

	// Expected routing key in I2P base64url (- and _ instead of + and /)
	expectedB64url := "vc4-qqPqRlgybuqknKxCJXjMrn8Y-qBvZN4aeRG0ltw="
	expectedBytes, err := base64.URLEncoding.DecodeString(expectedB64url)
	require.NoError(t, err, "base64url decode of expected routing key")
	require.Len(t, expectedBytes, 32)

	var h [32]byte
	copy(h[:], rawHash)

	// Use midnight UTC of 2026-06-26 (any time that day works because only the
	// date component is used).
	date := time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)

	got := RoutingKey(h, date)

	require.Equal(t, expectedBytes, got[:],
		"routing key mismatch for date 20260626: got %x want %x", got, expectedBytes)
}

// TestRoutingKey_DateRollover verifies that RoutingKey produces different values
// on adjacent days (midnight boundary), confirming date sensitivity.
func TestRoutingKey_DateRollover(t *testing.T) {
	var h [32]byte
	h[0] = 0xAB

	day1 := time.Date(2026, 6, 25, 23, 59, 59, 0, time.UTC)
	day2 := time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)

	rk1 := RoutingKey(h, day1)
	rk2 := RoutingKey(h, day2)

	require.NotEqual(t, rk1, rk2, "routing key must change at UTC midnight")
}

// TestRoutingKey_SameDaySameValue verifies determinism within a day.
func TestRoutingKey_SameDaySameValue(t *testing.T) {
	var h [32]byte
	h[1] = 0xCC

	t1 := time.Date(2026, 6, 26, 8, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 26, 22, 59, 59, 0, time.UTC)

	require.Equal(t, RoutingKey(h, t1), RoutingKey(h, t2),
		"routing key must be stable throughout a UTC calendar day")
}

// TestRoutingKey_LocalTimezoneUsesUTC verifies that even a non-UTC time.Time value
// is converted to UTC before extracting the date, so a caller in UTC+X won't
// accidentally produce the wrong key near midnight.
func TestRoutingKey_LocalTimezoneUsesUTC(t *testing.T) {
	var h [32]byte
	h[2] = 0xFF

	// 2026-06-26 01:00 UTC+12 = 2026-06-25 13:00 UTC — same UTC date as day1
	loc := time.FixedZone("UTC+12", 12*3600)
	nonUTC := time.Date(2026, 6, 26, 1, 0, 0, 0, loc) // local 2026-06-26, but UTC is still 2026-06-25

	utcEquiv := time.Date(2026, 6, 25, 13, 0, 0, 0, time.UTC)

	require.Equal(t, RoutingKey(h, nonUTC), RoutingKey(h, utcEquiv),
		"RoutingKey must use UTC date regardless of input timezone")
}
