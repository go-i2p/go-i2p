package i2np

import "github.com/go-i2p/logger"

/*
I2P I2NP ShortTunnelBuildReply
https://geti2p.net/spec/i2np
Added in version 0.9.51

Format:
+----+----+----+----+----+----+----+----+
| num| ShortBuildResponseRecords...
+----+----+----+----+----+----+----+----+

num ::
       1 byte Integer
       Valid values: 1-8

record size: 218 bytes (ElGamal/AES) or variable (ECIES)
total size: 1+$num*218 (for ElGamal/AES records)
*/

type ShortTunnelBuildReply struct {
	Count                int
	BuildResponseRecords []BuildResponseRecord
}

// GetResponseRecords returns the build response records
func (s *ShortTunnelBuildReply) GetResponseRecords() []BuildResponseRecord {
	return s.BuildResponseRecords
}

// GetRecordCount returns the number of response records
func (s *ShortTunnelBuildReply) GetRecordCount() int {
	return s.Count
}

// NewShortTunnelBuildReply creates a new ShortTunnelBuildReply
func NewShortTunnelBuildReply(records []BuildResponseRecord) *ShortTunnelBuildReply {
	log.WithFields(logger.Fields{
		"at":           "NewShortTunnelBuildReply",
		"record_count": len(records),
	}).Debug("Creating ShortTunnelBuildReply")

	return &ShortTunnelBuildReply{
		Count:                len(records),
		BuildResponseRecords: records,
	}
}
