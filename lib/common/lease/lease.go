// Package lease implements the I2P lease common data structure
package lease

import (
	"encoding/binary"
	"errors"
	"time"

	. "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/logger"
	"github.com/sirupsen/logrus"
)

// Sizes in bytes of various components of a Lease
const (
	LEASE_SIZE           = 44
	LEASE_TUNNEL_GW_SIZE = 32
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

var log = logger.GetGoI2PLogger()

type Lease [LEASE_SIZE]byte

// TunnelGateway returns the tunnel gateway as a Hash.
func (lease Lease) TunnelGateway() (hash Hash) {
	copy(hash[:], lease[:LEASE_TUNNEL_GW_SIZE])
	return
}

// TunnelID returns the tunnel id as a uint23.
func (lease Lease) TunnelID() uint32 {
	i := Integer(lease[LEASE_TUNNEL_GW_SIZE : LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE])
	return uint32(
		i.Int(),
	)
}

// Date returns the date as an I2P Date.
func (lease Lease) Date() (date Date) {
	copy(date[:], lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:])
	return
}

// ReadLease returns Lease from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadLease(data []byte) (lease Lease, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Reading Lease from bytes")

	if len(data) < LEASE_SIZE {
		err = errors.New("error parsing lease: not enough data")
		log.WithFields(logrus.Fields{
			"data_length":     len(data),
			"required_length": LEASE_SIZE,
		}).Error("Failed to read lease: insufficient data")
		return
	}

	copy(lease[:], data[:LEASE_SIZE])
	remainder = data[LEASE_SIZE:]

	log.WithFields(logrus.Fields{
		"tunnel_id":        lease.TunnelID(),
		"expiration":       lease.Date().Time(),
		"remainder_length": len(remainder),
	}).Debug("Successfully read Lease")

	return
}

// NewLease creates a new Lease with the provided parameters.
func NewLease(tunnelGateway Hash, tunnelID uint32, expirationTime time.Time) (*Lease, error) {
	log.Debug("Creating new Lease")

	var lease Lease

	// Gateway hash
	copy(lease[:LEASE_TUNNEL_GW_SIZE], tunnelGateway[:])

	// Convert and copy tunnel ID
	tunnelIDBytes := make([]byte, LEASE_TUNNEL_ID_SIZE)
	binary.BigEndian.PutUint32(tunnelIDBytes, tunnelID)
	copy(lease[LEASE_TUNNEL_GW_SIZE:LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE], tunnelIDBytes)

	// Convert and copy expiration date
	millis := expirationTime.UnixNano() / int64(time.Millisecond)
	dateBytes := make([]byte, DATE_SIZE)
	binary.BigEndian.PutUint64(dateBytes, uint64(millis))
	copy(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], dateBytes)

	log.WithFields(logrus.Fields{
		"tunnel_id":  tunnelID,
		"expiration": expirationTime,
	}).Debug("Successfully created new Lease")

	return &lease, nil
}

// NewLeaseFromBytes creates a new *Lease from []byte using ReadLease.
// Returns a pointer to Lease unlike ReadLease.
func NewLeaseFromBytes(data []byte) (lease *Lease, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Creating Lease from bytes")

	var l Lease
	l, remainder, err = ReadLease(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Lease from bytes")
		return nil, remainder, err
	}

	lease = &l

	log.WithFields(logrus.Fields{
		"tunnel_id":        lease.TunnelID(),
		"expiration":       lease.Date().Time(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created Lease from bytes")

	return
}
