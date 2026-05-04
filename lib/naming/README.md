# naming
--
    import "github.com/go-i2p/go-i2p/lib/naming"

![naming.svg](naming.svg)

Package naming provides hostname resolution for I2P destinations.

The default implementation uses an embedded hosts.txt file from the Java I2P
router distribution, which maps .i2p hostnames to their base64-encoded
Destination representations.

## Usage

#### func  DestinationToB32

```go
func DestinationToB32(destBytes []byte) string
```
DestinationToB32 is a package-level convenience function to convert destination
bytes to a .b32.i2p address string.

#### func  ResolveB32Address

```go
func ResolveB32Address(address string) ([]byte, error)
```
ResolveB32Address is a package-level convenience function to decode a .b32.i2p
address. It returns the 32-byte hash, not the full destination. For full
destination resolution with NetDB lookup, use HostsTxtResolver.Resolve().

#### type HostsTxtResolver

```go
type HostsTxtResolver struct {
}
```

HostsTxtResolver resolves .i2p hostnames using an in-memory map loaded from a
hosts.txt file. The default embedded hosts.txt is from the Java I2P router
distribution.

For .b32.i2p addresses, if a NetDB is configured, the resolver will look up the
destination in the NetDB and return the full destination bytes.

#### func  NewHostsTxtResolver

```go
func NewHostsTxtResolver() (*HostsTxtResolver, error)
```
NewHostsTxtResolver creates a resolver preloaded with the embedded default
hosts.txt from the Java I2P router.

#### func (*HostsTxtResolver) AddHostsFile

```go
func (r *HostsTxtResolver) AddHostsFile(path string) error
```
AddHostsFile loads additional hostname entries from a file on disk. This can be
called after initialization to add address book subscriptions or user-maintained
hosts files. Entries from the file override any existing entries with the same
hostname.

#### func (*HostsTxtResolver) DestinationToB32

```go
func (r *HostsTxtResolver) DestinationToB32(destBytes []byte) string
```
DestinationToB32 converts a raw Destination to its .b32.i2p address. The
destination bytes are SHA-256 hashed and base32-encoded.

#### func (*HostsTxtResolver) LoadAddressBooksFromDir

```go
func (r *HostsTxtResolver) LoadAddressBooksFromDir(dir string) error
```
LoadAddressBooksFromDir loads all hosts.txt files from a directory. Files are
loaded in alphabetical order, with later files overriding earlier entries for
the same hostname.

#### func (*HostsTxtResolver) Resolve

```go
func (r *HostsTxtResolver) Resolve(address string) ([]byte, bool, error)
```
Resolve resolves an I2P address (either a hostname or .b32.i2p address). For
regular hostnames, returns the full Destination bytes. For .b32.i2p addresses:

    - If a NetDB is configured, performs a LeaseSet lookup and returns the full destination.
    - If no NetDB is configured, returns the 32-byte hash with isHash=true.

#### func (*HostsTxtResolver) ResolveB32Address

```go
func (r *HostsTxtResolver) ResolveB32Address(address string) ([]byte, error)
```
ResolveB32Address resolves a .b32.i2p address to its raw hash bytes. The input
can be either just the 52-character hash or the full address including the
".b32.i2p" suffix.

Note: B32 addresses are a hash of the destination, so this function returns the
hash bytes (32 bytes), not the full destination. To resolve to a full
destination, use the Resolve method with a NetDB configured.

#### func (*HostsTxtResolver) ResolveHostname

```go
func (r *HostsTxtResolver) ResolveHostname(hostname string) ([]byte, error)
```
ResolveHostname resolves an I2P hostname to its raw Destination bytes. Returns
the destination bytes and nil on success, or nil and an error if the hostname is
not found.

#### func (*HostsTxtResolver) SetNetDB

```go
func (r *HostsTxtResolver) SetNetDB(netdb LeaseSetLookup)
```
SetNetDB configures the resolver to use the provided NetDB for .b32.i2p lookups.
When a NetDB is set, Resolve() will perform LeaseSet lookups for b32 addresses
to return the full destination bytes instead of just the hash.

#### func (*HostsTxtResolver) Size

```go
func (r *HostsTxtResolver) Size() int
```
Size returns the number of hostnames loaded in the resolver.

#### type LeaseSetLookup

```go
type LeaseSetLookup interface {
	// GetLeaseSet returns a channel that yields the LeaseSet for the given hash,
	// or a closed channel if not found.
	GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet
}
```

LeaseSetLookup is the interface required to look up LeaseSets in the NetDB. This
is used to resolve .b32.i2p addresses to full destinations.



naming 

github.com/go-i2p/go-i2p/lib/naming

[go-i2p template file](template.md)
