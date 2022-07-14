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

	log "github.com/sirupsen/logrus"
)

type Mapping struct {
	size *Integer
	vals *MappingValues
}

//
// Returns the values contained in a Mapping in the form of a MappingValues.
//
func (mapping Mapping) Values() MappingValues {
	if mapping.vals == nil {
		return MappingValues{}
	}
	return *mapping.vals
}

func (mapping *Mapping) Data() []byte {
	bytes := mapping.size.Bytes()
	for _, pair := range mapping.Values() {
		klen, _ := pair[0].Length()
		keylen, _ := NewIntegerFromInt(klen)
		bytes = append(bytes, keylen.Bytes()...)
		bytes = append(bytes, pair[0]...)
		vlen, _ := pair[1].Length()
		vallen, _ := NewIntegerFromInt(vlen)
		bytes = append(bytes, vallen.Bytes()...)
		bytes = append(bytes, pair[1]...)
	}
	return bytes
}

//
// Return true if two keys in a mapping are identical.
//
func (mapping *Mapping) HasDuplicateKeys() bool {
	seen_values := make(map[string]bool)
	values := mapping.Values()
	for _, pair := range values {
		key, _ := pair[0].Data()
		if _, present := seen_values[key]; present {
			return true
		} else {
			seen_values[key] = true
		}
	}
	return false
}

//
// Convert a Go map of unformatted strings to a sorted Mapping.
//
func GoMapToMapping(gomap map[string]string) (mapping *Mapping, err error) {
	map_vals := MappingValues{}
	for k, v := range gomap {
		key_str, kerr := ToI2PString(k)
		if kerr != nil {
			err = kerr
			return
		}
		val_str, verr := ToI2PString(v)
		if verr != nil {
			err = verr
			return
		}
		map_vals = append(
			map_vals,
			[2]I2PString{key_str, val_str},
		)
	}
	mapping = ValuesToMapping(map_vals)
	return
}

//
// Check if the string parsing error indicates that the Mapping
// should no longer be parsed.
//
func stopValueRead(err error) bool {
	return err.Error() == "error parsing string: zero length"
}

//
// Determine if the first byte in a slice of bytes is the provided byte.
//
func beginsWith(bytes []byte, chr byte) bool {
	return len(bytes) != 0 &&
		bytes[0] == chr
}

func ReadMapping(bytes []byte) (mapping Mapping, remainder []byte, err []error) {
	if len(bytes) == 0 {
		log.WithFields(log.Fields{
			"at":     "ReadMapping",
			"reason": "zero length",
		}).Warn("mapping format violation")
		e := errors.New("zero length")
		err = append(err, e)
	}
	size, remainder, e := NewInteger(bytes)
	err = append(err, e)
	mapping.size = size
	if err != nil {
		log.WithFields(log.Fields{
			"at":     "ReadMapping",
			"reason": "error parsing integer",
		}).Warn("mapping format violation")
		e := errors.New("error parsing integer")
		err = append(err, e)
	}
	if len(remainder) == 0 {
		log.WithFields(log.Fields{
			"at":     "ReadMapping",
			"reason": "zero length",
		}).Warn("mapping format violation")
		e := errors.New("zero length")
		err = append(err, e)
	}
	vals, remainder, e := ReadMappingValues(remainder)
	err = append(err, e)
	mapping.vals = vals
	if err != nil {
		log.WithFields(log.Fields{
			"at":     "ReadMapping",
			"reason": "error parsing mapping values",
		}).Warn("mapping format violation")
		e := errors.New("error parsing mapping values")
		err = append(err, e)
	}
	return
}

func NewMapping(bytes []byte) (values *Mapping, remainder []byte, err []error) {
	objvalues, remainder, err := ReadMapping(bytes)
	values = &objvalues
	return
}
