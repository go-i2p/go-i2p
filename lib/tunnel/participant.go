package tunnel

import (
	"github.com/go-i2p/crypto"
)

type Participant struct {
	decryption *crypto.Tunnel
}
