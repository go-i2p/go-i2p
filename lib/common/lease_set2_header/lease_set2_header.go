package lease_set2_header

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
