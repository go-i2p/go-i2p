package data

import (
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
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
		log.Debug("Mapping values are nil, returning empty MappingValues")
		return MappingValues{}
	}
	log.WithFields(logrus.Fields{
		"values_count": len(*mapping.vals),
	}).Debug("Retrieved Mapping values")
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
	log.Debug("Checking for duplicate keys in Mapping")
	seen_values := make(map[string]bool)
	values := mapping.Values()
	for _, pair := range values {
		key, _ := pair[0].Data()
		if _, present := seen_values[key]; present {
			log.WithFields(logrus.Fields{
				"duplicate_key": key,
			}).Warn("Found duplicate key in Mapping")
			return true
		} else {
			seen_values[key] = true
		}
	}
	log.Debug("No duplicate keys found in Mapping")
	return false
}

// GoMapToMapping converts a Go map of unformatted strings to *Mapping.
func GoMapToMapping(gomap map[string]string) (mapping *Mapping, err error) {
	log.WithFields(logrus.Fields{
		"input_map_size": len(gomap),
	}).Debug("Converting Go map to Mapping")
	map_vals := MappingValues{}
	for k, v := range gomap {
		key_str, kerr := ToI2PString(k)
		if kerr != nil {
			log.WithError(kerr).Error("Failed to convert key to I2PString")
			err = kerr
			return
		}
		val_str, verr := ToI2PString(v)
		if verr != nil {
			log.WithError(verr).Error("Failed to convert value to I2PString")
			err = verr
			return
		}
		map_vals = append(
			map_vals,
			[2]I2PString{key_str, val_str},
		)
	}
	mapping = ValuesToMapping(map_vals)
	log.WithFields(logrus.Fields{
		"mapping_size": len(map_vals),
	}).Debug("Successfully converted Go map to Mapping")
	return
}

// Check if the string parsing error indicates that the Mapping
// should no longer be parsed.
func stopValueRead(err error) bool {
	result := err.Error() == "error parsing string: zero length"
	if result {
		log.WithError(err).Debug("Stopping value read due to zero length error")
	}
	return result
}

// Determine if the first byte in a slice of bytes is the provided byte.
func beginsWith(bytes []byte, chr byte) bool {
	/*
		return len(bytes) != 0 &&
			bytes[0] == chr
	*/
	result := len(bytes) != 0 && bytes[0] == chr
	log.WithFields(logrus.Fields{
		"bytes_length":  len(bytes),
		"expected_char": string(chr),
		"result":        result,
	}).Debug("Checked if bytes begin with specific character")
	return result
}

// ReadMapping returns Mapping from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadMapping(bytes []byte) (mapping Mapping, remainder []byte, err []error) {
	log.WithFields(logrus.Fields{
		"input_length": len(bytes),
	}).Debug("Reading Mapping from bytes")
	if len(bytes) < 3 {
		log.WithFields(logrus.Fields{
			"at":     "ReadMapping",
			"reason": "zero length",
		}).Warn("mapping format violation")
		e := oops.Errorf("zero length")
		err = append(err, e)
		return
	}
	size, remainder, e := NewInteger(bytes, 2)
	if e != nil {
		log.WithError(e).Error("Failed to read Mapping size")
		err = append(err, e)
	}
	mapping.size = size
	if size.Int() == 0 {
		log.Warn("Mapping size is zero")
		return
	}
	// Length Check
	if len(remainder) < size.Int() {
		log.WithFields(logrus.Fields{
			"expected_size": size.Int(),
			"actual_size":   len(remainder),
		}).Warn("mapping format violation: mapping length exceeds provided data")
		e := oops.Errorf("warning parsing mapping: mapping length exceeds provided data")
		err = append(err, e)

		// Use whatever data is available (recovery)
		map_bytes := remainder
		remainder = nil

		vals, _, mappingValueErrs := ReadMappingValues(map_bytes, *size)
		err = append(err, mappingValueErrs...)
		mapping.vals = vals
		return
	}

	// Proceed normally if enough data is present
	map_bytes := remainder[:size.Int()]
	remainder = remainder[size.Int():]

	vals, _, mappingValueErrs := ReadMappingValues(map_bytes, *size)
	err = append(err, mappingValueErrs...)
	mapping.vals = vals
	if len(mappingValueErrs) > 0 {
		log.WithFields(logrus.Fields{
			"at":     "ReadMapping",
			"reason": "error parsing mapping values",
		}).Warn("mapping format violation")
		e := oops.Errorf("error parsing mapping values")
		err = append(err, e)
	}
	if len(remainder) > 0 { // Handle extra bytes beyond mapping length
		log.WithFields(logrus.Fields{
			"expected_size": size.Int(),
			"actual_size":   len(remainder),
		}).Error("mapping format violation: data exists beyond length of mapping")
		e := oops.Errorf("warning parsing mapping: data exists beyond length of mapping")
		err = append(err, e)

		// Slice the exact mapping bytes
		/* // Don't attempt recovery, can cause panics
		map_bytes := remainder[:size.Int()]
		remainder = remainder[size.Int():]

		vals, _, mappingValueErrs := ReadMappingValues(map_bytes, *size)
		err = append(err, mappingValueErrs...)
		mapping.vals = vals
		*/
		return
	}

	log.WithFields(logrus.Fields{
		"mapping_size":     size.Int(),
		"values_count":     len(*mapping.vals),
		"remainder_length": len(remainder),
		"error_count":      len(err),
	}).Debug("Finished reading Mapping")

	return
}

// NewMapping creates a new *Mapping from []byte using ReadMapping.
// Returns a pointer to Mapping unlike ReadMapping.
func NewMapping(bytes []byte) (values *Mapping, remainder []byte, err []error) {
	log.WithFields(logrus.Fields{
		"input_length": len(bytes),
	}).Debug("Creating new Mapping")

	objvalues, remainder, err := ReadMapping(bytes)
	values = &objvalues

	log.WithFields(logrus.Fields{
		"values_count":     len(values.Values()),
		"remainder_length": len(remainder),
		"error_count":      len(err),
	}).Debug("Finished creating new Mapping")
	return
}
