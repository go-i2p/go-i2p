package data

import (
	"fmt"
	"reflect"
	"testing"
)

func TestMappingOrderSortsValuesThenKeys(t *testing.T) {
	a, _ := ToI2PString("a")
	b, _ := ToI2PString("b")
	aa, _ := ToI2PString("aa")
	ab, _ := ToI2PString("ab")
	ac, _ := ToI2PString("ac")
	values := MappingValues{
		[2]I2PString{b, b},
		[2]I2PString{ac, a},
		[2]I2PString{ab, b},
		[2]I2PString{aa, a},
		[2]I2PString{a, a},
	}
	mappingOrder(values)
	for i, pair := range values {
		key, _ := pair[0].Data()
		switch i {
		case 0:
			if !(key == "a") {
				t.Fatal(fmt.Sprintf("mappingOrder expected key a, got %s at index", key), i)
			}
		case 1:
			if !(key == "aa") {
				t.Fatal(fmt.Sprintf("mappingOrder expected key aa, got %s at index", key), i)
			}
		case 2:
			if !(key == "ab") {
				t.Fatal(fmt.Sprintf("mappingOrder expected key ab, got %s at index", key), i)
			}
		case 3:
			if !(key == "ac") {
				t.Fatal(fmt.Sprintf("mappingOrder expected key ac, got %s at index", key), i)
			}
		case 4:
			if !(key == "b") {
				t.Fatal(fmt.Sprintf("mappingOrder expected key b, got %s at index", key), i)
			}
		}
	}
}

func TestMappingValuesEdgeCases(t *testing.T) {
	k1, _ := ToI2PString("test")
	tests := []struct {
		name string
		mv   MappingValues
		key  I2PString
		want I2PString
	}{
		{
			name: "nil key",
			mv:   MappingValues{},
			key:  nil,
			want: nil,
		},
		{
			name: "empty mapping",
			mv:   MappingValues{},
			key:  k1,
			want: nil,
		},
		{
			name: "nil value in pair",
			mv:   MappingValues{{k1, nil}},
			key:  k1,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mv.Get(tt.key)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MappingValues.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}
