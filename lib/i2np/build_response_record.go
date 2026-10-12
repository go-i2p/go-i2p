package i2np

import (
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
)

// BuildResponseRecord is a type alias for buildrecord.BuildResponseRecord,
// the canonical definition. Both lib/tunnel and lib/i2np share this type
// without import cycles. Parsing, serialization, and accessor methods are
// defined in lib/tunnel/buildrecord.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the wire format.
// See also [BuildRequestRecord].
type BuildResponseRecord = buildrecord.BuildResponseRecord

// Re-export functions from buildrecord package
var (
	// ReadBuildResponseRecord parses a BuildResponseRecord from the provided
	// byte slice. It delegates to buildrecord.ReadBuildResponseRecord.
	ReadBuildResponseRecord = buildrecord.ReadBuildResponseRecord

	// ValidateBuildResponseRecord checks that the record's hash matches
	// SHA256(randomData + reply byte), which binds the reply to the
	// original build request. It delegates to
	// buildrecord.ValidateBuildResponseRecord.
	ValidateBuildResponseRecord = buildrecord.ValidateBuildResponseRecord
)
