package exportable

import "github.com/go-i2p/go-i2p/lib/i2np"

func Fuzz(data []byte) int {
	// Fuzz test - we don't care about errors, just that it doesn't panic
	_, _ = i2np.ReadI2NPNTCPHeader(data)
	return 1
}
