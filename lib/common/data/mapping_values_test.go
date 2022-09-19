package data

import (
	"testing"
)

func TestMappingOrderSortsValuesThenKeys(t *testing.T) {
	a, _ := ToI2PString("a")
	b, _ := ToI2PString("b")
	values := MappingValues{
		[2]I2PString{b, b},
		[2]I2PString{b, a},
		[2]I2PString{a, b},
		[2]I2PString{a, a},
	}
	mappingOrder(values)
	for i, pair := range values {
		key, _ := pair[0].Data()
		value, _ := pair[1].Data()
		switch i {
		case 0:
			if !(key == "a" && value == "a") {
				t.Fatal("mappingOrder produced incorrect sort output at", i)
			}
		case 1:
			if !(key == "a" && value == "b") {
				t.Fatal("mappingOrder produced incorrect sort output at", i)
			}
		case 2:
			if !(key == "b" && value == "a") {
				t.Fatal("mappingOrder produced incorrect sort output at", i)
			}
		case 3:
			if !(key == "b" && value == "b") {
				t.Fatal("mappingOrder produced incorrect sort output at", i)
			}
		}
	}
}
