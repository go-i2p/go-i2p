package i2np

/*
I2P I2NP TunnelBuildReply
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

Same format as TunnelBuildMessage, with BuildResponseRecords
*/

type TunnelBuildReply [8]BuildResponseRecord

// GetReplyRecords returns the build response records
func (t *TunnelBuildReply) GetReplyRecords() []BuildResponseRecord {
	return t[:]
}

// ProcessReply processes the tunnel build reply
func (t *TunnelBuildReply) ProcessReply() error {
	// Implementation would depend on business logic
	// This is a placeholder for the interface requirement
	return nil
}

// Compile-time interface satisfaction check
var _ TunnelReplyHandler = (*TunnelBuildReply)(nil)
