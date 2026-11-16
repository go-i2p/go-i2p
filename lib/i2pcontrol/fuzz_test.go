package i2pcontrol

import (
	"testing"
)

// FuzzI2CPControlAuth exercises the I2PControl request parser (ParseRequest),
// which decodes the JSON-RPC framing of every control request — including the
// Authenticate call that carries the operator password. This is the i2cp-auth
// parse surface the C3 audit flagged as unfuzzed: a panic while parsing a
// remote-supplied request would crash the I2PControl handler.
func FuzzI2CPControlAuth(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not json"))
	f.Add([]byte(`{"method":"Authenticate","params":{"Password":"x"},"id":1,"version":"4","name":"I2PControl"}`))
	f.Add([]byte(`{"method":`))
	f.Add([]byte(`{"method":"Authenticate","params":{"Password":`))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must return an error on malformed input, not panic.
		_, _ = ParseRequest(data)
	})
}
