package keys

import "testing"

// assertNotAllZeros fails the test if all bytes in data are zero.
func assertNotAllZeros(t testing.TB, data []byte, msg string) {
	t.Helper()
	for _, b := range data {
		if b != 0 {
			return
		}
	}
	t.Fatal(msg)
}

// assertAllZeros fails the test if any byte in data is non-zero.
func assertAllZeros(t testing.TB, data []byte, msg string) {
	t.Helper()
	for _, b := range data {
		if b != 0 {
			t.Error(msg)
			return
		}
	}
}
