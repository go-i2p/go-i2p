package exportable

import common "github.com/go-i2p/go-i2p/lib/common/data"

func Fuzz(data []byte) int {
	str := common.I2PString(data)
	str.Data()
	str.Length()
	str, _ = common.ToI2PString(string(data))
	str.Data()
	str.Length()
	return 0
}
