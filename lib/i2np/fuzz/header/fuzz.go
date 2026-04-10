package header

import "github.com/go-i2p/go-i2p/lib/i2np"

// Fuzz is a go-fuzz entry point that feeds arbitrary data into the I2NP NTCP header parser to detect panics.
func Fuzz(data []byte) int {
	// Fuzz test - we don't care about errors, just that it doesn't panic
	_, _ = i2np.ReadI2NPNTCPHeader(data)
	return 1
}
