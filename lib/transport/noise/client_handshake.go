package noise

import (
	"github.com/flynn/noise"
)

func ComposeInitiatorHandshakeMessage(s noise.DHKey, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {

	return
}

func (c *NoiseSession) RunClientHandshake() error {

	return nil
}
