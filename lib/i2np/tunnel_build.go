package i2np

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

type TunnelBuild [8]BuildRequestRecord

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

// Compile-time interface satisfaction check
var _ TunnelBuilder = (*TunnelBuild)(nil)
