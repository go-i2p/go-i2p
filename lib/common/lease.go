package common

import (
	"errors"
	log "github.com/sirupsen/logrus"
)

/*
I2P Lease
https://geti2p.net/spec/common-structures#lease
Accurate for version 0.9.24

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

// Sizes or various components of a Lease
const (
	LEASE_SIZE             = 44
	LEASE_HASH_SIZE        = 32
	LEASE_TUNNEL_ID_SIZE   = 4
	LEASE_TUNNEL_DATE_SIZE = 8
)

type LeaseInterface interface {
	TunnelGateway() (hash Hash)
	TunnelID() uint32
	Date() (date Date)
}

type Lease struct {
	LeaseHash   Hash
	TunnelIdent *Integer
	TunnelDate  Date
} //[LEASE_SIZE]byte

var li LeaseInterface = &Lease{}

//
// Return the first 32 bytes of the Lease as a Hash.
//
func (lease Lease) TunnelGateway() (hash Hash) {
	copy(hash[:], lease.LeaseHash[:])
	return
}

//
// Return the TunnelID Integer in the Lease.
//
func (lease Lease) TunnelID() uint32 {
	return uint32(lease.TunnelIdent.Value())
}

//
// Return the Date inside the Lease.
//
func (lease Lease) Date() (date Date) {
	copy(date[:], lease.TunnelDate[:])
	return
}

//
// Possibly temporary? Just to make it compile for now
//
func (lease Lease) Bytes() (bytes []byte) {
	var r []byte
	r = append(r, lease.LeaseHash[:]...)
	r = append(r, lease.TunnelIdent.Bytes()...)
	r = append(r, lease.TunnelDate[:]...)
	return r
}

func ReadLease(data []byte) (lease Lease, remainder []byte, err error) {
	if len(data) < LEASE_SIZE {
		log.WithFields(log.Fields{
			"at":           "(Lease) ReadLease",
			"data_len":     len(data),
			"required_len": "44",
			"reason":       "lease missing data",
		}).Error("error parsnig lease")
		err = errors.New("error parsing lease: lease missing data")
	}
	lease.LeaseHash, remainder, err = ReadHash(data)
	identbytes, remainder, err := ReadIdent(remainder)
	lease.TunnelIdent, err = NewInteger(identbytes[:])
	lease.TunnelDate, remainder, err = ReadDate(remainder)
	return
}
