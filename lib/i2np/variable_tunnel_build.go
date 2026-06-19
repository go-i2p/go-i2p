package i2np

import "github.com/go-i2p/logger"

/*
I2P I2NP VariableTunnelBuild
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+
| num| BuildRequestRecords...
+----+----+----+----+----+----+----+----+

Same format as TunnelBuildMessage, except for the addition of a $num field
in front and $num number of BuildRequestRecords instead of 8

num ::
       1 byte Integer
       Valid values: 1-8

record size: 528 bytes
total size: 1+$num*528
*/

// VariableTunnelBuild represents an I2NP VariableTunnelBuild message containing a variable number of build request records for tunnel construction.
type VariableTunnelBuild struct {
	sliceRecordSet
}

// NewVariableTunnelBuilder creates a new VariableTunnelBuild and returns it as TunnelBuilder interface
func NewVariableTunnelBuilder(records []BuildRequestRecord) TunnelBuilder {
	log.WithFields(logger.Fields{
		"at":           "NewVariableTunnelBuilder",
		"record_count": len(records),
	}).Debug("Creating VariableTunnelBuild")

	return &VariableTunnelBuild{
		sliceRecordSet: sliceRecordSet{
			Count:               len(records),
			BuildRequestRecords: records,
		},
	}
}

// Compile-time interface satisfaction check
var _ TunnelBuilder = (*VariableTunnelBuild)(nil)
