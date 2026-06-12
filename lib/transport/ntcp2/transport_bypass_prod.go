package ntcp2

// isHandshakeBypassEnabled returns the value of testBypassHandshakeTypeCheck.
//
// M-NEW-5 FIX: Production code reaches this test-only escape hatch via this
// method rather than reading the struct field directly. This makes all call
// sites of the bypass auditable in one place.
//
// In production binaries the bypass is always false because NewNTCP2Transport
// never sets testBypassHandshakeTypeCheck. Only test code that builds transports
// directly via struct literals can set it, and only for mock connections.
func (t *NTCP2Transport) isHandshakeBypassEnabled() bool {
	return t.testBypassHandshakeTypeCheck
}
