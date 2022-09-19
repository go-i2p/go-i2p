// Package lease implements the I2P lease common data structure
package lease

import . "github.com/go-i2p/go-i2p/lib/common/data"

// Sizes in bytes of various components of a Lease
const (
	LEASE_SIZE           = 44
	LEASE_HASH_SIZE      = 32
	LEASE_TUNNEL_ID_SIZE = 4
)

/*
[Lease]
Accurate for version 0.9.49

Description
Defines the authorization for a particular tunnel to receive messages targeting a Destination.

Contents
SHA256 Hash of the RouterIdentity of the gateway router, then the TunnelId and finally an end Date.

+----+----+----+----+----+----+----+----+
| tunnel_gw                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|     tunnel_id     |      end_date
+----+----+----+----+----+----+----+----+
                    |
+----+----+----+----+

tunnel_gw :: Hash of the RouterIdentity of the tunnel gateway
             length -> 32 bytes

tunnel_id :: TunnelId
             length -> 4 bytes

end_date :: Date
            length -> 8 bytes
*/

// Lease is the represenation of an I2P Lease.
//
// https://geti2p.net/spec/common-structures#lease
type Lease [LEASE_SIZE]byte

// TunnelGateway returns the tunnel gateway as a Hash.
func (lease Lease) TunnelGateway() (hash Hash) {
	copy(hash[:], lease[:LEASE_HASH_SIZE])
	return
}

// TunnelID returns the tunnel id as a uint23.
func (lease Lease) TunnelID() uint32 {
	i := Integer(lease[LEASE_HASH_SIZE : LEASE_HASH_SIZE+LEASE_TUNNEL_ID_SIZE])
	return uint32(
		i.Int(),
	)
}

// Date returns the date as an I2P Date.
func (lease Lease) Date() (date Date) {
	copy(date[:], lease[LEASE_HASH_SIZE+LEASE_TUNNEL_ID_SIZE:])
	return
}

// ReadLease returns Lease from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadLease(data []byte) (lease Lease, remainder []byte, err error) {
	// TODO: stub
	return
}

// NewLease creates a new *NewLease from []byte using ReadLease.
// Returns a pointer to KeysAndCert unlike ReadLease.
func NewLease(data []byte) (lease *Lease, remainder []byte, err error) {
	// TODO: stub
	return
}
