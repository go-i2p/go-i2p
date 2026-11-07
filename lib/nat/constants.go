package nat

import "time"

// ──────────────────────────────────────────────────────────────────────────────
// Backoff defaults
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: backoff.go, port_mapper.go
const (
	// defaultBackoffInitial is the first retry delay for a failed NAT
	// port-mapping or bind attempt.
	defaultBackoffInitial = 30 * time.Second

	// defaultBackoffMax caps how long the retry delay may grow to.
	defaultBackoffMax = 30 * time.Minute

	// defaultBackoffFactor doubles the delay on each retry.
	defaultBackoffFactor = 2.0

	// defaultPortMappingLeaseDuration is how long a UPnP/NAT-PMP mapping is
	// requested to hold. A mapping that expires is re-established by the
	// retry goroutine.
	defaultPortMappingLeaseDuration = 1 * time.Hour
)

// ──────────────────────────────────────────────────────────────────────────────
// Bind defaults
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: nat.go
const (
	// defaultNATTimeout bounds a single NAT discovery or mapping operation.
	defaultNATTimeout = 3 * time.Second

	// defaultBindMaxRetries is how many times a bind is retried after a
	// TOCTOU failure before giving up.
	defaultBindMaxRetries = 5

	// defaultBindRetryBaseDelay is the base delay between bind retries,
	// before jitter is applied.
	defaultBindRetryBaseDelay = 50 * time.Millisecond

	// stopWaitTimeout is how long Stop() waits for the port-mapping retry
	// goroutine to exit before logging that the NAT operation may be hung.
	stopWaitTimeout = 30 * time.Second
)

// ──────────────────────────────────────────────────────────────────────────────
// Jitter
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: jitter.go
const (
	// jitterBytesLen is how many random bytes are drawn to build the jitter
	// fraction: two bytes give a 16-bit uniform sample.
	jitterBytesLen = 2

	// jitterUint16Range is the number of distinct values a 16-bit sample can
	// take, used as the divisor that maps the sample onto [0, 1).
	jitterUint16Range = 65536.0

	// jitterFactorMin and jitterFactorSpan define the ±25% window applied to
	// a base delay: the multiplier is jitterFactorMin + rand*jitterFactorSpan,
	// i.e. [0.75, 1.25).
	jitterFactorMin  = 0.75
	jitterFactorSpan = 0.5
)

// ──────────────────────────────────────────────────────────────────────────────
// Special-use IPv4 range leading octets (RFC 6890)
// ──────────────────────────────────────────────────────────────────────────────

// These are the first (and second) octets of the ranges IsSpecialUseIPv4
// rejects. Go's net.IP.IsPrivate covers only the RFC 1918 ranges, so the
// carrier-grade NAT, IETF-reserved, and TEST-NET blocks have to be matched
// explicitly — a router reporting one of them as its external address would
// advertise an endpoint no peer can reach.
//
// RFC 6890: https://www.rfc-editor.org/rfc/rfc6890
// Moved from: classify.go
const (
	// cgnatFirstOctet is the leading octet of 100.64.0.0/10. The /10 means the
	// second octet's top two bits are fixed, which cgnatSecondOctetMask tests.
	cgnatFirstOctet      = 100
	cgnatSecondOctetMask = 0xC0
	cgnatSecondOctetBits = 64

	// Leading octets of the /24 special-use blocks. Each block is matched on
	// its first three octets; the fourth is the host part.
	ietfProtoFirstOctet  = 192 // 192.0.0.0/24   IETF protocol assignments
	ietfProtoSecondOctet = 0
	ietfProtoThirdOctet  = 0

	testNet1FirstOctet  = 192 // 192.0.2.0/24    TEST-NET-1
	testNet1SecondOctet = 0
	testNet1ThirdOctet  = 2

	testNet2FirstOctet  = 198 // 198.51.100.0/24 TEST-NET-2
	testNet2SecondOctet = 51
	testNet2ThirdOctet  = 100

	testNet3FirstOctet  = 203 // 203.0.113.0/24  TEST-NET-3
	testNet3SecondOctet = 0
	testNet3ThirdOctet  = 113

	// multicastAndReservedFirstOctetFloor is the lowest leading octet that is
	// multicast or reserved (224.0.0.0/3 covers 224-255).
	multicastAndReservedFirstOctetFloor = 224
)
