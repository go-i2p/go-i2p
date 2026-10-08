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

// VariableTunnelBuild represents an I2NP VariableTunnelBuild message containing a variable number of build request records for tunnel construction.
//
// NOTE: This type is retained for receive-side parsing and spec-compliance
// record-count validation only. The send-side constructor has been removed —
// production builds use ShortTunnelBuild (STBM, type 25) exclusively.
type VariableTunnelBuild struct {
	sliceRecordSet
}

// Compile-time interface satisfaction check
var _ TunnelBuilder = (*VariableTunnelBuild)(nil)
