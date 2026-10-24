package naming

import "time"

// ──────────────────────────────────────────────────────────────────────────────
// Address format constants
// ──────────────────────────────────────────────────────────────────────────────

// B32AddressLength is the length of a base32-encoded I2P address
// excluding the ".b32.i2p" suffix. 256 bits encoded in base32
// produces 52 characters.
const B32AddressLength = 52

// B33AddressLength is the minimum length of an encrypted (b33) B32
// address excluding the ".b32.i2p" suffix. Encrypted addresses are
// longer than standard B32 addresses because they carry a public key
// plus signature-type and flag bytes. See the I2P spec "Encrypted B32
// Addresses" (b33).
const B33AddressLength = 56

// B32HashSize is the size in bytes of the SHA-256 hash used in
// .b32.i2p addresses.
const B32HashSize = 32

// ──────────────────────────────────────────────────────────────────────────────
// Network operation constants
// ──────────────────────────────────────────────────────────────────────────────

// DefaultFetchTimeout is the maximum time to wait for a NetDB
// LeaseSet lookup before returning a timeout error.
const DefaultFetchTimeout = 10 * time.Second
