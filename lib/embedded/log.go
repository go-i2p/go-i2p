package embedded

import (
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
)

func init() {
	// Ensure DEBUG_I2P=info (and unrecognized → info) applies for
	// library/embed consumers that never import main.
	logutil.ApplyDebugI2PEnv()
}

var log = logger.GetGoI2PLogger()
