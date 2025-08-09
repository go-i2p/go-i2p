package i2np

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

type VariableTunnelBuild struct {
	Count               int
	BuildRequestRecords []BuildRequestRecord
}

// GetBuildRecords returns the build request records
func (v *VariableTunnelBuild) GetBuildRecords() []BuildRequestRecord {
	return v.BuildRequestRecords
}

// GetRecordCount returns the number of build records
func (v *VariableTunnelBuild) GetRecordCount() int {
	return v.Count
}

// NewVariableTunnelBuilder creates a new VariableTunnelBuild and returns it as TunnelBuilder interface
func NewVariableTunnelBuilder(records []BuildRequestRecord) TunnelBuilder {
	return &VariableTunnelBuild{
		Count:               len(records),
		BuildRequestRecords: records,
	}
}

// Compile-time interface satisfaction check
var _ TunnelBuilder = (*VariableTunnelBuild)(nil)
