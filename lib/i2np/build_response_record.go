package i2np

import (
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
)

// Type alias for BuildResponseRecord - canonical definition in lib/tunnel/buildrecord
type BuildResponseRecord = buildrecord.BuildResponseRecord

// Re-export functions from buildrecord package
var (
	ReadBuildResponseRecord     = buildrecord.ReadBuildResponseRecord
	ValidateBuildResponseRecord = buildrecord.ValidateBuildResponseRecord
)
