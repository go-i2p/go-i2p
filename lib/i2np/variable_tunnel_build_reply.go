package i2np

/*
I2P I2NP VariableTunnelBuildReply
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+
| num| BuildResponseRecords...
+----+----+----+----+----+----+----+----+

Same format as VariableTunnelBuildMessage, with BuildResponseRecords.
*/

type VariableTunnelBuildReply struct {
	Count                int
	BuildResponseRecords []BuildResponseRecord
}

// GetReplyRecords returns the build response records
func (v *VariableTunnelBuildReply) GetReplyRecords() []BuildResponseRecord {
	return v.BuildResponseRecords
}

// ProcessReply processes the variable tunnel build reply
func (v *VariableTunnelBuildReply) ProcessReply() error {
	// Implementation would depend on business logic
	// This is a placeholder for the interface requirement
	return nil
}

// Compile-time interface satisfaction check
var _ TunnelReplyHandler = (*VariableTunnelBuildReply)(nil)
