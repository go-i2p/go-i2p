package tunnel

import (
	"github.com/go-i2p/go-i2p/lib/crypto"
)

type Participant struct {
	decryption *crypto.Tunnel
}
