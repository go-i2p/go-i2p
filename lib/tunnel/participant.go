package tunnel

import (
	"github.com/go-i2p/crypto/tunnel"
)

type Participant struct {
	decryption tunnel.TunnelEncryptor
}
