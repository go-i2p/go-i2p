package lease2

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	. "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/util/logger"
	"github.com/sirupsen/logrus"
	"time"
)

// Sizes in bytes of various components of a Lease
const (
	LEASE2_SIZE           = 40
	LEASE2_TUNNEL_GW_SIZE = 32
	LEASE2_TUNNEL_ID_SIZE = 4
	LEASE2_END_DATE_SIZE  = 4
)

/*
[Lease2]
Accurate for version 0.9.63

Description
Defines the authorization for a particular tunnel to receive messages targeting a Destination. Same as Lease but with a 4-byte end_date. Used by LeaseSet2. Supported as of 0.9.38; see proposal 123 for more information.

Contents
SHA256 Hash of the RouterIdentity of the gateway router, then the TunnelId, and finally a 4 byte end date.

+----+----+----+----+----+----+----+----+
| tunnel_gw                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|     tunnel_id     |      end_date     |
+----+----+----+----+----+----+----+----+

tunnel_gw :: Hash of the RouterIdentity of the tunnel gateway
             length -> 32 bytes

tunnel_id :: TunnelId
             length -> 4 bytes

end_date :: 4 byte date
            length -> 4 bytes
            Seconds since the epoch, rolls over in 2106.

//https://geti2p.net/spec/common-structures#lease2

*/

var log = logger.GetGoI2PLogger()

type Lease2 [LEASE2_SIZE]byte

// TunnelGateway returns the tunnel gateway as a Hash.
func (lease Lease2) TunnelGateway() (hash Hash) {
	copy(hash[:], lease[:LEASE2_TUNNEL_GW_SIZE])
	return
}

// TunnelID returns the tunnel ID as a uint32.
func (lease Lease2) TunnelID() uint32 {
	i := Integer(lease[LEASE2_TUNNEL_GW_SIZE : LEASE2_TUNNEL_GW_SIZE+LEASE2_TUNNEL_ID_SIZE])
	return uint32(i.Int())
}

// EndDate returns the end date as a time.Time.
// The end date is a 4-byte field representing seconds since the epoch.
func (lease Lease2) EndDate() time.Time {
	millis := binary.BigEndian.Uint32(lease[LEASE2_TUNNEL_GW_SIZE+LEASE2_TUNNEL_ID_SIZE:])
	// Convert seconds since epoch to time.Time
	return time.Unix(int64(millis), 0).UTC()
}

// ReadLease2 reads a Lease2 from a byte slice.
// It returns the Lease2, any remaining bytes, and an error if parsing fails.
func ReadLease2(data []byte) (lease Lease2, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Reading Lease2 from bytes")

	if len(data) < LEASE2_SIZE {
		err = errors.New("error parsing Lease2: not enough data")
		log.WithFields(logrus.Fields{
			"data_length":     len(data),
			"required_length": LEASE2_SIZE,
		}).Error("Failed to read Lease2: insufficient data")
		return
	}

	copy(lease[:], data[:LEASE2_SIZE])
	remainder = data[LEASE2_SIZE:]

	log.WithFields(logrus.Fields{
		"tunnel_id":        lease.TunnelID(),
		"end_date":         lease.EndDate(),
		"remainder_length": len(remainder),
	}).Debug("Successfully read Lease2")

	return
}

// NewLease2 creates a new Lease2 with the provided parameters.
// It returns a pointer to the Lease2 and an error if any.
func NewLease2(tunnelGateway Hash, tunnelID uint32, endDate time.Time) (*Lease2, error) {
	log.Debug("Creating new Lease2")

	var lease Lease2

	// Copy tunnel gateway hash
	copy(lease[:LEASE2_TUNNEL_GW_SIZE], tunnelGateway[:])

	// Convert and copy tunnel ID
	binary.BigEndian.PutUint32(lease[LEASE2_TUNNEL_GW_SIZE:LEASE2_TUNNEL_GW_SIZE+LEASE2_TUNNEL_ID_SIZE], tunnelID)

	// Convert and copy end date (seconds since epoch)
	seconds := uint32(endDate.UTC().Unix())
	binary.BigEndian.PutUint32(lease[LEASE2_TUNNEL_GW_SIZE+LEASE2_TUNNEL_ID_SIZE:], seconds)

	log.WithFields(logrus.Fields{
		"tunnel_id": tunnelID,
		"end_date":  endDate.UTC(),
	}).Debug("Successfully created new Lease2")

	return &lease, nil
}

// NewLease2FromBytes creates a new *Lease2 from a byte slice using ReadLease2.
// It returns the Lease2, any remaining bytes, and an error if parsing fails.
func NewLease2FromBytes(data []byte) (lease *Lease2, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Creating Lease2 from bytes")

	var l Lease2
	l, remainder, err = ReadLease2(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Lease2 from bytes")
		return nil, remainder, err
	}

	lease = &l

	log.WithFields(logrus.Fields{
		"tunnel_id":        lease.TunnelID(),
		"end_date":         lease.EndDate(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created Lease2 from bytes")

	return
}

// ToBytes serializes the Lease2 into a byte slice.
func (lease Lease2) ToBytes() []byte {
	return lease[:]
}

// String returns a human-readable representation of the Lease2.
func (lease Lease2) String() string {
	// Assign the TunnelGateway to a variable first to make it addressable
	hash := lease.TunnelGateway()
	tunnelGWHex := hex.EncodeToString(hash[:])

	return fmt.Sprintf("Lease2{TunnelGateway: %s, TunnelID: %d, EndDate: %s}",
		tunnelGWHex,
		lease.TunnelID(),
		lease.EndDate().Format(time.RFC3339))
}
