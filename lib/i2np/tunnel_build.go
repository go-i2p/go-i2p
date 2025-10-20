package i2np

import (
	"github.com/samber/oops"
)

/*
I2P I2NP TunnelBuild
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+
| Record 0 ...                          |

|                                       |
+----+----+----+----+----+----+----+----+
| Record 1 ...                          |

~ .....                                 ~
|                                       |
+----+----+----+----+----+----+----+----+
| Record 7 ...                          |

|                                       |
+----+----+----+----+----+----+----+----+

Just 8 BuildRequestRecords attached together
record size: 528 bytes
total size: 8*528 = 4224 bytes
*/

// TunnelBuild represents the raw 8 build request records
type TunnelBuild [8]BuildRequestRecord

// TunnelBuildMessage wraps TunnelBuild to implement I2NPMessage interface
type TunnelBuildMessage struct {
	*BaseI2NPMessage
	Records TunnelBuild
}

// GetBuildRecords returns the build request records
func (t *TunnelBuild) GetBuildRecords() []BuildRequestRecord {
	return t[:]
}

// GetRecordCount returns the number of build records
func (t *TunnelBuild) GetRecordCount() int {
	return 8
}

// NewTunnelBuilder creates a new TunnelBuild and returns it as TunnelBuilder interface
func NewTunnelBuilder(records [8]BuildRequestRecord) TunnelBuilder {
	tb := TunnelBuild(records)
	return &tb
}

// NewTunnelBuildMessage creates a new TunnelBuild I2NP message
func NewTunnelBuildMessage(records [8]BuildRequestRecord) *TunnelBuildMessage {
	msg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_BUILD),
		Records:         TunnelBuild(records),
	}

	// Create placeholder data for I2NP compatibility (8 records * 528 bytes each)
	// In production, this would need proper BuildRequestRecord serialization
	data := make([]byte, 8*528)
	msg.SetData(data)

	return msg
}

// GetBuildRecords implements TunnelBuilder interface
func (msg *TunnelBuildMessage) GetBuildRecords() []BuildRequestRecord {
	return msg.Records[:]
}

// GetRecordCount implements TunnelBuilder interface
func (msg *TunnelBuildMessage) GetRecordCount() int {
	return 8
}

// MarshalBinary serializes the TunnelBuild message using BaseI2NPMessage
func (msg *TunnelBuildMessage) MarshalBinary() ([]byte, error) {
	return msg.BaseI2NPMessage.MarshalBinary()
}

// UnmarshalBinary deserializes the TunnelBuild message
func (msg *TunnelBuildMessage) UnmarshalBinary(data []byte) error {
	if err := msg.BaseI2NPMessage.UnmarshalBinary(data); err != nil {
		return oops.Wrapf(err, "failed to unmarshal base I2NP message")
	}

	recordData := msg.GetData()
	if len(recordData) != 8*528 {
		return oops.Errorf("invalid TunnelBuild data size: expected %d bytes, got %d", 8*528, len(recordData))
	}

	// Parse records from data (placeholder - would need proper deserialization)
	for i := 0; i < 8; i++ {
		record, err := ReadBuildRequestRecord(recordData[i*528 : (i+1)*528])
		if err != nil {
			return oops.Wrapf(err, "failed to parse build request record %d", i)
		}
		msg.Records[i] = record
	}

	return nil
}

// Compile-time interface satisfaction checks
var _ TunnelBuilder = (*TunnelBuild)(nil)
var _ TunnelBuilder = (*TunnelBuildMessage)(nil)
var _ I2NPMessage = (*TunnelBuildMessage)(nil)
