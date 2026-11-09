package reseed

import "time"

// ──────────────────────────────────────────────────────────────────────────────
// Reseed HTTP client tuning
// ──────────────────────────────────────────────────────────────────────────────

// A reseed fetch is a single large download over a tunnel-free HTTPS connection,
// so the timeouts below are generous compared to interactive traffic but still
// bounded: a reseed server that cannot deliver in these windows is unreachable
// for practical purposes and the caller should move on to the next one.
//
// The dial timeout and keep-alive are not repeated here - see DefaultDialTimeout
// and DefaultKeepAlive in new.go.
//
// Moved from: reseed.go
const (
	// defaultReseedRequestTimeout bounds one whole reseed request, from dial
	// through body close. It is the outer deadline that keeps a stalled server
	// from hanging the bootstrap goroutine indefinitely.
	defaultReseedRequestTimeout = 30 * time.Second

	// reseedTLSHandshakeTimeout bounds only the TLS negotiation, so a server
	// that accepts TCP but stalls the handshake fails fast instead of consuming
	// the whole request budget.
	reseedTLSHandshakeTimeout = 10 * time.Second

	// reseedIdleConnTimeout is how long an unused pooled connection is kept.
	// Reseed servers are contacted in bursts (one bundle per candidate), so the
	// window is set well past the gap between successive requests to make the
	// pool actually save handshakes.
	reseedIdleConnTimeout = 90 * time.Second

	// reseedMaxIdleConns caps idle connections held across all reseed hosts.
	reseedMaxIdleConns = 10

	// reseedMaxIdleConnsPerHost caps idle connections held to any single reseed
	// host. Kept low because one reseed needs at most a request or two per host.
	reseedMaxIdleConnsPerHost = 2
)

// ──────────────────────────────────────────────────────────────────────────────
// Reseed payload size floors
// ──────────────────────────────────────────────────────────────────────────────

// minSU3FileSize is the smallest response that can plausibly be a real reseed
// payload, checked both against the declared Content-Length and against the
// bytes actually buffered. A genuine SU3 bundle carries a signed manifest, a
// signature block and a zip of RouterInfos, so anything this short is an error
// page or a truncated stream rather than seeds. Rejecting it here keeps the SU3
// parser from dereferencing short buffers.
//
// Moved from: reseed.go
const minSU3FileSize = 100

// ──────────────────────────────────────────────────────────────────────────────
// Zip-bomb limit units
// ──────────────────────────────────────────────────────────────────────────────

// Divisors that turn the byte-valued zip limits (maxPerEntrySize,
// maxDecompressedSize) into the human-readable KB/MB figures their error
// messages report.
//
// Moved from: reseed.go
const (
	// bytesPerKiB is the divisor for a kilobyte of bytes.
	bytesPerKiB = 1024

	// bytesPerMiB is the divisor for a mebibyte of bytes, composed from
	// bytesPerKiB so the two units cannot drift apart.
	bytesPerMiB = bytesPerKiB * 1024
)

// ──────────────────────────────────────────────────────────────────────────────
// Reseed temporary file permissions
// ──────────────────────────────────────────────────────────────────────────────

// The reseed zip and its extraction directory are world-readable by default
// under a permissive umask, which would let another local account read the
// RouterInfo arrival order and timing. Both are therefore explicitly narrowed to
// owner-only before any seed data is written.
//
// Moved from: reseed.go
const (
	// reseedTempFileMode is the permission for the staged reseed zip file.
	reseedTempFileMode = 0o600

	// reseedTempDirMode is the permission for the extraction directory.
	reseedTempDirMode = 0o700
)
