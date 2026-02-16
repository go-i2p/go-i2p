package i2np

import "github.com/go-i2p/logger"

/*
I2P I2NP ShortTunnelBuild
https://geti2p.net/spec/i2np
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

record size: 218 bytes (ElGamal/AES) or variable (ECIES)
total size: 1+$num*218 (for ElGamal/AES records)

Note: ECIES-X25519 records are variable length and more compact.
The modern I2P network uses ECIES primarily, with ElGamal/AES for backward compatibility.
*/

type ShortTunnelBuild struct {
	Count               int
	BuildRequestRecords []BuildRequestRecord
}

// GetBuildRecords returns the build request records
func (s *ShortTunnelBuild) GetBuildRecords() []BuildRequestRecord {
	return s.BuildRequestRecords
}

// GetRecordCount returns the number of build records
func (s *ShortTunnelBuild) GetRecordCount() int {
	return s.Count
}

// NewShortTunnelBuilder creates a new ShortTunnelBuild and returns it as TunnelBuilder interface.
// This is the modern, preferred format for tunnel building (added in I2P 0.9.51).
func NewShortTunnelBuilder(records []BuildRequestRecord) TunnelBuilder {
	log.WithFields(logger.Fields{
		"at":           "NewShortTunnelBuilder",
		"record_count": len(records),
	}).Debug("Creating ShortTunnelBuild")

	return &ShortTunnelBuild{
		Count:               len(records),
		BuildRequestRecords: records,
	}
}

// Bytes serializes the ShortTunnelBuild message to wire format.
// Format: [count:1][records...]
// Each record is 218 bytes per the I2P specification (ECIES short records).
// The caller is responsible for applying ECIES encryption to each record.
func (s *ShortTunnelBuild) Bytes() []byte {
	log.WithFields(logger.Fields{
		"at":           "ShortTunnelBuild.Bytes",
		"record_count": s.Count,
		"output_size":  1 + (s.Count * ShortBuildRecordSize),
	}).Debug("Serializing ShortTunnelBuild")

	// 1 byte for count + 218 bytes per record (ECIES short format)
	size := 1 + (s.Count * ShortBuildRecordSize)
	data := make([]byte, size)

	// Write count
	data[0] = byte(s.Count)

	// Write each record in short ECIES format
	offset := 1
	for _, record := range s.BuildRequestRecords {
		recordBytes := record.ShortBytes()
		copy(data[offset:offset+ShortBuildRecordSize], recordBytes)
		offset += ShortBuildRecordSize
	}

	return data
}

// Compile-time interface satisfaction check
var _ TunnelBuilder = (*ShortTunnelBuild)(nil)
