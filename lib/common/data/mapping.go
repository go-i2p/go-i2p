package data

import (
	"errors"
	"fmt"

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
func GoMapToMapping(gomap map[string]string) (*Mapping, error) {
	map_vals := MappingValues{}
	for k, v := range gomap {
		key_str, err := ToI2PString(k)
		if err != nil {
			return nil, fmt.Errorf("key conversion error: %w", err)
		}
		val_str, err := ToI2PString(v)
		if err != nil {
			return nil, fmt.Errorf("value conversion error: %w", err)
		}
		map_vals = append(map_vals, [2]I2PString{key_str, val_str})
	}
	return ValuesToMapping(map_vals), nil
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

func (mapping *Mapping) addValue(key, value I2PString) error {
	for _, pair := range *mapping.vals {
		existingKey, _ := pair[0].Data()
		newKey, _ := key.Data()
		if existingKey == newKey {
			return fmt.Errorf("duplicate key: %s", newKey)
		}
	}
	*mapping.vals = append(*mapping.vals, [2]I2PString{key, value})
	return nil
}

// ReadMapping returns Mapping from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
const MaxMappingSize = 65535 // Match Java I2P's maximum mapping size

func ReadMapping(bytes []byte) (mapping Mapping, remainder []byte, err []error) {
	if len(bytes) < 3 {
		err = append(err, errors.New("mapping data too short"))
		return
	}
	size, remainder, e := NewInteger(bytes, 2)
	if e != nil {
		log.WithError(e).Error("Failed to read Mapping size")
		err = append(err, e)
	}
	if size.Int() > MaxMappingSize {
		err = append(err, fmt.Errorf("mapping size %d exceeds maximum %d", size.Int(), MaxMappingSize))
		return
	}
	log.WithFields(logrus.Fields{
		"input_length": len(bytes),
	}).Debug("Reading Mapping from bytes")
	if len(bytes) < 3 {
		log.WithFields(logrus.Fields{
			"at":     "ReadMapping",
			"reason": "zero length",
		}).Warn("mapping format violation")
		e := errors.New("zero length")
		err = append(err, e)
		return
	}
	if size.Int() == 0 {
		log.Warn("Mapping size is zero")
		return
	}
	mapping.size = size
	if mapping.size.Int() > len(remainder) {
		err = append(err, fmt.Errorf("mapping size %d exceeds available data length %d",
			mapping.size.Int(), len(remainder)))
		return
	}
	map_bytes := remainder[:mapping.size.Int()]
	remainder = remainder[mapping.size.Int():]
	if len(remainder) == 0 {
		log.WithFields(logrus.Fields{
			"at":     "ReadMapping",
			"reason": "zero length",
		}).Warn("mapping format violation")
		e := errors.New("zero length")
		err = append(err, e)
	}
	// TODO: this should take the remainder and the length we already parsed above, as a parameter.
	// Like tomorrow morning.
	// ReadMappingValues should not attempt to figure out the length of the bytes it's reading over.
	vals, _, mappingValueErrs := ReadMappingValues(map_bytes, *mapping.size)

	err = append(err, mappingValueErrs...)
	mapping.vals = vals
	if len(mappingValueErrs) > 0 {
		log.WithFields(logrus.Fields{
			"at":     "ReadMapping",
			"reason": "error parsing mapping values",
		}).Warn("mapping format violation")
		e := errors.New("error parsing mapping values")
		err = append(err, e)
	}

	log.WithFields(logrus.Fields{
		"mapping_size":     mapping.size.Int(),
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
