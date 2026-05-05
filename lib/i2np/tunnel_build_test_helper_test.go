package i2np

import (
	"github.com/go-i2p/crypto/rand"
)

// newTunnelBuildMessage is test-only legacy construction for cleartext record layout tests.
// Production code must use NewEncryptedTunnelBuildMessage or tunnel manager encryption paths.
func newTunnelBuildMessage(records [8]BuildRequestRecord) *TunnelBuildMessage {
	msg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeTunnelBuild),
		Records:         TunnelBuild(records),
		encrypted:       true,
	}

	data := make([]byte, 8*528)
	for i := 0; i < 8; i++ {
		cleartext := records[i].Bytes()
		copy(data[i*528:i*528+222], cleartext)
		if _, err := rand.Read(data[i*528+222 : (i+1)*528]); err != nil {
			// Keep deterministic layout behavior for tests even if CSPRNG fails.
		}
	}
	msg.SetData(data)
	return msg
}
