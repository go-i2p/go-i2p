package i2np

import "github.com/go-i2p/logger"

/*
I2P I2NP ShortTunnelBuild
https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
Added in version 0.9.51

Short Tunnel Build Messages (STBM) are the modern standard for tunnel building.
They use shorter build records (218 bytes instead of 528 bytes) and are preferred
by all current I2P routers.

Format:
+----+----+----+----+----+----+----+----+
| num| ShortBuildRequestRecords...
+----+----+----+----+----+----+----+----+

num ::
       1 byte Integer
       Valid values: 1-8

record size: 218 bytes
total size: 1+$num*218
*/

// ShortTunnelBuild represents an I2NP ShortTunnelBuild message, a modern compact format for tunnel build requests introduced in I2P 0.9.51.
// It uses 218-byte short build records instead of the 528-byte standard
// records, which makes it the preferred format for building tunnels today.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the wire format.
// See also [ShortTunnelBuildReply].
type ShortTunnelBuild struct {
	sliceRecordSet
}

// NewShortTunnelBuilder creates a new ShortTunnelBuild and returns it as TunnelBuilder interface.
// This is the modern, preferred format for tunnel building (added in I2P 0.9.51).
// See also [ShortTunnelBuild].
func NewShortTunnelBuilder(records []BuildRequestRecord) TunnelBuilder {
	log.WithFields(logger.Fields{
		"at":           "NewShortTunnelBuilder",
		"record_count": len(records),
	}).Debug("Creating ShortTunnelBuild")

	return &ShortTunnelBuild{
		sliceRecordSet: sliceRecordSet{
			Count:               len(records),
			BuildRequestRecords: records,
		},
	}
}

// Wire serialization for this message is deliberately NOT implemented here.
// The live outbound path builds a type 25 message from already-encrypted
// records via build.BuildMessageFactory.CreateShortTunnelBuildMessage
// (lib/i2np/build_message_factory.go:61), which emits the spec's
// "[count:1][218-byte encrypted records...]" layout (i2np.rst:1682-1706)
// inside a full I2NP header. A previous Bytes() method on this type serialized
// the cleartext records produced by BuildRequestRecord.ShortBytes(), which
// zeroes the 32-byte ephemeral-key slot (tunnel/buildrecord/
// build_request_record.go:396-405). That output was never a valid build
// message and no caller used it, so it has been removed rather than fixed.

// Compile-time interface satisfaction check
var _ TunnelBuilder = (*ShortTunnelBuild)(nil)
