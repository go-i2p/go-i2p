# lease
--
    import "github.com/go-i2p/go-i2p/lib/common/lease"

Package lease implements the I2P lease common data structure

## Usage

```go
const (
	LEASE_SIZE           = 44
	LEASE_TUNNEL_GW_SIZE = 32
	LEASE_TUNNEL_ID_SIZE = 4
)
```
Sizes in bytes of various components of a Lease

#### type Lease

```go
type Lease [LEASE_SIZE]byte
```

Lease is the represenation of an I2P Lease.

https://geti2p.net/spec/common-structures#lease

#### func  NewLease

```go
func NewLease(data []byte) (lease *Lease, remainder []byte, err error)
```
NewLease creates a new *NewLease from []byte using ReadLease. Returns a pointer
to KeysAndCert unlike ReadLease.

#### func  ReadLease

```go
func ReadLease(data []byte) (lease Lease, remainder []byte, err error)
```
ReadLease returns Lease from a []byte. The remaining bytes after the specified
length are also returned. Returns a list of errors that occurred during parsing.

#### func (Lease) Date

```go
func (lease Lease) Date() (date Date)
```
Date returns the date as an I2P Date.

#### func (Lease) TunnelGateway

```go
func (lease Lease) TunnelGateway() (hash Hash)
```
TunnelGateway returns the tunnel gateway as a Hash.

#### func (Lease) TunnelID

```go
func (lease Lease) TunnelID() uint32
```
TunnelID returns the tunnel id as a uint23.
