package data

/*
I2P Mapping
https://geti2p.net/spec/common-structures#mapping
Accurate for version 0.9.24

+----+----+----+----+----+----+----+----+
|  size   |key_string (len + data) | =  |
+----+----+----+----+----+----+----+----+
| val_string (len + data)     | ;  | ...
+----+----+----+----+----+----+----+
size :: Integer
        length -> 2 bytes
        Total number of bytes that follow

key_string :: String
              A string (one byte length followed by UTF-8 encoded characters)

= :: A single byte containing '='

val_string :: String
              A string (one byte length followed by UTF-8 encoded characters)

; :: A single byte containing ';'
*/

import (
	"errors"
	"sort"

	log "github.com/sirupsen/logrus"
)

// Parsed key-values pairs inside a Mapping.
type MappingValues [][2]I2PString

//
// Convert a MappingValue struct to a Mapping.  The values are first
// sorted in the order defined in mappingOrder.
//
func ValuesToMapping(values MappingValues) (mapping *Mapping) {
	mapping.size, _ = NewIntegerFromInt(len(values))
	mapping.vals = &values
	return
}

type byValue MappingValues

func (set byValue) Len() int      { return len(set) }
func (set byValue) Swap(i, j int) { set[i], set[j] = set[j], set[i] }
func (set byValue) Less(i, j int) bool {
	data1, _ := set[i][1].Data()
	data2, _ := set[j][1].Data()
	return data1 < data2
}

type byKey MappingValues

func (set byKey) Len() int      { return len(set) }
func (set byKey) Swap(i, j int) { set[i], set[j] = set[j], set[i] }
func (set byKey) Less(i, j int) bool {
	data1, _ := set[i][0].Data()
	data2, _ := set[j][0].Data()
	return data1 < data2
}

//
// I2P Mappings require consistent order for for cryptographic signing, and sorting
// by keys.  When new Mappings are created, they are stable sorted first by values
// than by keys to ensure a consistent order.
//
func mappingOrder(values MappingValues) {
	sort.Stable(byValue(values))
	sort.Stable(byKey(values))
}

func ReadMappingValues(remainder []byte) (values *MappingValues, remainder_bytes []byte, err error) {
	var str I2PString
	mapping := remainder
	//var remainder = mapping
	//var err error
	if remainder == nil || len(remainder) < 0 {
		log.WithFields(log.Fields{
			"at":     "(Mapping) Values",
			"reason": "data shorter than expected",
		}).Error("mapping contained no data")
		err = errors.New("mapping contained no data")
		return
	}
	var errs []error
	map_values := make(MappingValues, 0)
	if len(remainder) < 2 {
		log.WithFields(log.Fields{
			"at":     "(Mapping) Values",
			"reason": "data shorter than expected",
		}).Error("mapping contained no data")
		err = errors.New("mapping contained no data")
		return
	}
	l := Integer(remainder[:2])
	length := l.Int()
	inferred_length := length + 2
	remainder = remainder[2:]
	mapping_len := len(mapping)
	if mapping_len > inferred_length {
		log.WithFields(log.Fields{
			"at":                    "(Mapping) Values",
			"mappnig_bytes_length":  mapping_len,
			"mapping_length_field":  length,
			"expected_bytes_length": inferred_length,
			"reason":                "data longer than expected",
		}).Warn("mapping format warning")
		errs = append(errs, errors.New("warning parsing mapping: data exists beyond length of mapping"))
	} else if inferred_length > mapping_len {
		log.WithFields(log.Fields{
			"at":                    "(Mapping) Values",
			"mappnig_bytes_length":  mapping_len,
			"mapping_length_field":  length,
			"expected_bytes_length": inferred_length,
			"reason":                "data shorter than expected",
		}).Warn("mapping format warning")
		errs = append(errs, errors.New("warning parsing mapping: mapping length exceeds provided data"))
	}

	for {
		// Read a key, breaking on fatal errors
		// and appending warnings
		str, remainder, err = ReadI2PString(remainder)
		key_str := str
		if err != nil {
			if stopValueRead(err) {
				errs = append(errs, err)
				//return
			}
		}
		if !beginsWith(remainder, 0x3d) {
			log.WithFields(log.Fields{
				"at":     "(Mapping) Values",
				"reason": "expected =",
			}).Warn("mapping format violation")
			errs = append(errs, errors.New("mapping format violation, expected ="))
			//return
		}
		remainder = remainder[1:]

		// Read a value, breaking on fatal errors
		// and appending warnings
		str, remainder, err = ReadI2PString(remainder)
		val_str := str
		if err != nil {
			if stopValueRead(err) {
				errs = append(errs, err)
				//return
			}
		}
		if !beginsWith(remainder, 0x3b) {
			log.WithFields(log.Fields{
				"at":     "(Mapping) Values",
				"reason": "expected ;",
			}).Warn("mapping format violation")
			errs = append(errs, errors.New("mapping format violation, expected ;"))
			//return
		}
		remainder = remainder[1:]

		// Append the key-value pair and break if there is no more data to read
		map_values = append(map_values, [2]I2PString{key_str, val_str})
		if len(remainder) == 0 {
			break
		}
	}
	values = &map_values
	return

}
