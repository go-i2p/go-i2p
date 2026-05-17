package i2np

import (
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
)

// Type aliases for BuildResponseRecord types - canonical definitions now in lib/tunnel/buildrecord
type (
	BuildResponseRecord           = buildrecord.BuildResponseRecord
	BuildResponseRecordELGamalAES = buildrecord.BuildResponseRecordELGamalAES
	BuildResponseRecordELGamal    = buildrecord.BuildResponseRecordELGamal
)

// Re-export functions from buildrecord package
var (
	ReadBuildResponseRecord     = buildrecord.ReadBuildResponseRecord
	ValidateBuildResponseRecord = buildrecord.ValidateBuildResponseRecord
)
