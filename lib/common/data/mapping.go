package data

import (
	"errors"

	log "github.com/sirupsen/logrus"
)

/*
[I2P Mapping]
Accurate for version 0.9.49

Description
A set of key/value mappings or properties


Contents
A 2-byte size Integer followed by a series of String=String; pairs

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

// Mapping is the represenation of an I2P Mapping.
//
// https://geti2p.net/spec/common-structures#mapping
type Mapping struct {
	size *Integer
	vals *MappingValues
}

// Values returns the values contained in a Mapping as MappingValues.
func (mapping Mapping) Values() MappingValues {
	if mapping.vals == nil {
		return MappingValues{}
	}
	return *mapping.vals
}

// Data returns a Mapping in its []byte form.
func (mapping *Mapping) Data() []byte {
	keyOrValIntegerLength := 1
	bytes := mapping.size.Bytes()
	for _, pair := range mapping.Values() {
		klen, _ := pair[0].Length()
		keylen, _ := NewIntegerFromInt(klen, keyOrValIntegerLength)
		bytes = append(bytes, keylen.Bytes()...)
		bytes = append(bytes, pair[0][1:]...)
		bytes = append(bytes, 0x3d)
		vlen, _ := pair[1].Length()
		vallen, _ := NewIntegerFromInt(vlen, keyOrValIntegerLength)
		bytes = append(bytes, vallen.Bytes()...)
		bytes = append(bytes, pair[1][1:]...)
		bytes = append(bytes, 0x3b)
	}
	return bytes
}

// HasDuplicateKeys returns true if two keys in a mapping are identical.
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

// GoMapToMapping converts a Go map of unformatted strings to *Mapping.
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

// Check if the string parsing error indicates that the Mapping
// should no longer be parsed.
func stopValueRead(err error) bool {
	return err.Error() == "error parsing string: zero length"
}

// Determine if the first byte in a slice of bytes is the provided byte.
func beginsWith(bytes []byte, chr byte) bool {
	return len(bytes) != 0 &&
		bytes[0] == chr
}

// ReadMapping returns Mapping from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadMapping(bytes []byte) (mapping Mapping, remainder []byte, err []error) {
	if len(bytes) == 0 {
		log.WithFields(log.Fields{
			"at":     "ReadMapping",
			"reason": "zero length",
		}).Warn("mapping format violation")
		e := errors.New("zero length")
		err = append(err, e)
	}
	size, remainder, e := NewInteger(bytes, 2)
	if e != nil {
		err = append(err, e)
	}
	mapping.size = size
	log.Println("Mapping Size:", mapping.size.Int())
	log.Println("Remainder Size:", len(remainder))
	if e != nil {
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
	// TODO: this should take the remainder and the length we already parsed above, as a parameter.
	// Like tomorrow morning.
	// ReadMappingValues should not attempt to figure out the length of the bytes it's reading over.
	vals, remainder, mappingValueErrs := ReadMappingValues(remainder, *mapping.size)

	err = append(err, mappingValueErrs...)
	mapping.vals = vals
	if len(mappingValueErrs) > 0 {
		log.WithFields(log.Fields{
			"at":     "ReadMapping",
			"reason": "error parsing mapping values",
		}).Warn("mapping format violation")
		e := errors.New("error parsing mapping values")
		err = append(err, e)
	}
	return
}

// NewMapping creates a new *Mapping from []byte using ReadMapping.
// Returns a pointer to Mapping unlike ReadMapping.
func NewMapping(bytes []byte) (values *Mapping, remainder []byte, err []error) {
	objvalues, remainder, err := ReadMapping(bytes)
	values = &objvalues
	return
}
