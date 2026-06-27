package naming

import "time"

// B32AddressLength is the length of a base32-encoded I2P address
// excluding the ".b32.i2p" suffix. 256 bits encoded in base32
// produces 52 characters.
const B32AddressLength = 52

// B32HashSize is the size in bytes of the SHA-256 hash used in
// .b32.i2p addresses.
const B32HashSize = 32

// DefaultFetchTimeout is the maximum time to wait for a NetDB
// LeaseSet lookup before returning a timeout error.
const DefaultFetchTimeout = 10 * time.Second

// MaxSubscriptionSize is the maximum number of entries allowed
// in a single address book subscription to prevent memory
// exhaustion from overly large hosts files.
const MaxSubscriptionSize = 10000
