package lease_set2_header

import (
	"encoding/binary"
	"errors"
	"github.com/go-i2p/go-i2p/lib/common/destination"
	"github.com/go-i2p/go-i2p/lib/common/offline_signature"
	log "github.com/sirupsen/logrus"
)

const (
	LEASE_SET2_HEADER_MAX_SIZE       = 395
	LEASE_SET2_HEADER_PUBLISHED_SIZE = 4
	LEASE_SET2_HEADER_EXPIRY_SIZE    = 2
)

/*
[LeaseSet2Header]
Accurate for version 0.9.63

Description
This is the common part of the LeaseSet2 and MetaLeaseSet. Supported as of 0.9.38; see proposal 123 for more information.

Contents
Contains the Destination, two timestamps, and an optional OfflineSignature.

+----+----+----+----+----+----+----+----+
| destination                           |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|     published     | expires |  flags  |
+----+----+----+----+----+----+----+----+
| offline_signature (optional)          |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

destination :: Destination
               length -> >= 387+ bytes

published :: 4 byte date
             length -> 4 bytes
             Seconds since the epoch, rolls over in 2106.

expires :: 2 byte time
           length -> 2 bytes
           Offset from published timestamp in seconds, 18.2 hours max

flags :: 2 bytes
  Bit order: 15 14 ... 3 2 1 0
  Bit 0: If 0, no offline keys; if 1, offline keys
  Bit 1: If 0, a standard published leaseset.
         If 1, an unpublished leaseset. Should not be flooded, published, or
         sent in response to a query. If this leaseset expires, do not query the
         netdb for a new one, unless bit 2 is set.
  Bit 2: If 0, a standard published leaseset.
         If 1, this unencrypted leaseset will be blinded and encrypted when published.
         If this leaseset expires, query the blinded location in the netdb for a new one.
         If this bit is set to 1, set bit 1 to 1 also.
         As of release 0.9.42.
  Bits 15-3: set to 0 for compatibility with future uses

offline_signature :: OfflineSignature
                     length -> varies
                     Optional, only present if bit 0 is set in the flags.

https://geti2p.net/spec/common-structures#leaseset2header

*/

// ParsedLeaseSet2Header holds the parsed LeaseSet2Header content.
type ParsedLeaseSet2Header struct {
	Destination      destination.Destination
	Published        uint32
	Expires          uint16
	Flags            uint16
	OfflineSignature *offline_signature.OfflineSignature
}

func (h *ParsedLeaseSet2Header) Serialize() []byte {
	data := h.Destination.Bytes()
	pub := make([]byte, 4)
	binary.BigEndian.PutUint32(pub, h.Published)
	data = append(data, pub...)

	exp := make([]byte, 2)
	binary.BigEndian.PutUint16(exp, h.Expires)
	data = append(data, exp...)

	fl := make([]byte, 2)
	binary.BigEndian.PutUint16(fl, h.Flags)
	data = append(data, fl...)

	if h.Flags&0x0001 != 0 && h.OfflineSignature != nil {
		data = append(data, h.OfflineSignature.Bytes()...)
	}
	return data
}

func ReadLeaseSet2Header(data []byte) (ParsedLeaseSet2Header, []byte, error) {
	var hdr ParsedLeaseSet2Header

	dest, remainder, err := destination.ReadDestination(data)
	if err != nil {
		log.WithError(err).Error("Failed to read destination from LeaseSet2Header")
		return hdr, data, err
	}
	hdr.Destination = dest

	if len(remainder) < 4 {
		return hdr, data, errors.New("not enough data for published")
	}
	hdr.Published = binary.BigEndian.Uint32(remainder[0:4])
	remainder = remainder[4:]

	if len(remainder) < 2 {
		return hdr, data, errors.New("not enough data for expires")
	}
	hdr.Expires = binary.BigEndian.Uint16(remainder[0:2])
	remainder = remainder[2:]

	if len(remainder) < 2 {
		return hdr, data, errors.New("not enough data for flags")
	}
	hdr.Flags = binary.BigEndian.Uint16(remainder[0:2])
	remainder = remainder[2:]

	// If offline keys bit is set (bit 0), read OfflineSignature
	if hdr.Flags&0x0001 != 0 {
		osig, r, err := offline_signature.ReadOfflineSignature(remainder)
		if err != nil {
			log.WithError(err).Error("Failed to read OfflineSignature from LeaseSet2Header")
			return hdr, data, err
		}
		hdr.OfflineSignature = &osig
		remainder = r
	}

	return hdr, remainder, nil
}
