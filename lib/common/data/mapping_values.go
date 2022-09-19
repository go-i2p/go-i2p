package data

import (
	"errors"
	"sort"

	log "github.com/sirupsen/logrus"
)

// MappingValues represents the parsed key value pairs inside of an I2P Mapping.
type MappingValues [][2]I2PString

// ValuesToMapping creates a *Mapping using MappingValues.
// The values are sorted in the order defined in mappingOrder.
func ValuesToMapping(values MappingValues) *Mapping {
	// Default length to 2 * len
	// 1 byte for ;
	// 1 byte for =
	baseLength := 2 * len(values)
	for _, mappingVals := range values {
		for _, keyOrVal := range mappingVals {
			baseLength += len(keyOrVal)
		}
	}

	mappingSize, _ := NewIntegerFromInt(baseLength, 2)
	return &Mapping{
		size: mappingSize,
		vals: &values,
	}
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

// TODO: This sort doesn't appear to work the same as ref implementation.
// It also appears to be unstable
func mappingOrder(values MappingValues) {
	sort.Stable(byValue(values))
	sort.Stable(byKey(values))
}

// ReadMappingValues returns *MappingValues from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadMappingValues(remainder []byte) (values *MappingValues, remainder_bytes []byte, errs []error) {
	mapping := remainder
	//var remainder = mapping
	//var err error
	if remainder == nil || len(remainder) < 0 {
		log.WithFields(log.Fields{
			"at":     "(Mapping) Values",
			"reason": "data shorter than expected",
		}).Error("mapping contained no data")
		errs = []error{errors.New("mapping contained no data")}
		return
	}
	map_values := make(MappingValues, 0)
	if len(remainder) < 1 {
		log.WithFields(log.Fields{
			"at":     "(Mapping) Values",
			"reason": "data shorter than expected",
		}).Error("mapping contained no data")
		errs = []error{errors.New("mapping contained no data")}
		return
	}
	l := Integer(remainder[:2])
	length := l.Int()
	// - 2 bytes for map length bits
	mapping_len := len(mapping) - 2
	if mapping_len > length {
		log.WithFields(log.Fields{
			"at":                   "(Mapping) Values",
			"mapping_bytes_length": mapping_len,
			"mapping_length_field": length,
			"reason":               "data longer than expected",
		}).Warn("mapping format warning")
		errs = append(errs, errors.New("warning parsing mapping: data exists beyond length of mapping"))
	} else if length > mapping_len {
		log.WithFields(log.Fields{
			"at":                   "(Mapping) Values",
			"mapping_bytes_length": mapping_len,
			"mapping_length_field": length,
			"reason":               "data shorter than expected",
		}).Warn("mapping format warning")
		errs = append(errs, errors.New("warning parsing mapping: mapping length exceeds provided data"))
	}

	// pop off length bytes before parsing kv pairs
	remainder = remainder[2:]

	for {
		// Read a key, breaking on fatal errors
		// and appending warnings

		// Minimum byte length required for another KV pair.
		// Two bytes for each string length
		// At least 1 byte per string
		// One byte for =
		// One byte for ;
		if len(remainder) < 6 {
			// Not returning an error here as the issue is already flagged by mapping length being wrong.
			log.WithFields(log.Fields{
				"at":     "(Mapping) Values",
				"reason": "mapping format violation",
			}).Warn("mapping format violation, too few bytes for a kv pair")
			break
		}

		str, more, err := ReadI2PString(remainder)
		// overwriting remainder with more as another var to prevent memory weirdness in loops
		remainder = more
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
			break
		}
		remainder = remainder[1:]

		// Read a value, breaking on fatal errors
		// and appending warnings
		str, more, err = ReadI2PString(remainder)
		// overwriting remainder with more as another var to prevent memory weirdness in loops
		remainder = more
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
			break
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
