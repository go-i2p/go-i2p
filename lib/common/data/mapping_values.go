package data

import (
	"errors"
	"github.com/sirupsen/logrus"
	"sort"
)

// MappingValues represents the parsed key value pairs inside of an I2P Mapping.
type MappingValues [][2]I2PString

func (m MappingValues) Get(key I2PString) I2PString {
	keyBytes, _ := key.Data()
	log.WithFields(logrus.Fields{
		"key": string(keyBytes),
	}).Debug("Searching for key in MappingValues")
	for _, pair := range m {
		kb, _ := pair[0][0:].Data()
		if kb == keyBytes {
			log.WithFields(logrus.Fields{
				"key":   string(keyBytes),
				"value": string(pair[1][1:]),
			}).Debug("Found matching key in MappingValues")
			return pair[1][1:]
		}
	}
	log.WithFields(logrus.Fields{
		"key": string(keyBytes),
	}).Debug("Key not found in MappingValues")
	return nil
}

// ValuesToMapping creates a *Mapping using MappingValues.
// The values are sorted in the order defined in mappingOrder.
func ValuesToMapping(values MappingValues) *Mapping {
	// Default length to 2 * len
	// 1 byte for ;
	// 1 byte for =
	log.WithFields(logrus.Fields{
		"values_count": len(values),
	}).Debug("Converting MappingValues to Mapping")
	baseLength := 2 * len(values)
	for _, mappingVals := range values {
		for _, keyOrVal := range mappingVals {
			baseLength += len(keyOrVal)
		}
	}

	log.WithFields(logrus.Fields{
		"mapping_size": baseLength,
	}).Debug("Created Mapping from MappingValues")

	mappingSize, _ := NewIntegerFromInt(baseLength, 2)
	return &Mapping{
		size: mappingSize,
		vals: &values,
	}
}

// I2P Mappings require consistent order in some cases for cryptographic signing, and sorting
// by keys. The Mapping is sorted lexographically by keys. Duplicate keys are allowed in general,
// but in implementations where they must be sorted like I2CP SessionConfig duplicate keys are not allowed.
// In practice routers do not seem to allow duplicate keys.
func mappingOrder(values MappingValues) {
	sort.SliceStable(values, func(i, j int) bool {
		// Lexographic sort on keys only
		data1, _ := values[i][0].Data()
		data2, _ := values[j][0].Data()
		return data1 < data2
	})
}

// ReadMappingValues returns *MappingValues from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadMappingValues(remainder []byte, map_length Integer) (values *MappingValues, remainder_bytes []byte, errs []error) {
	// mapping := remainder
	// var remainder = mapping
	// var err error
	log.WithFields(logrus.Fields{
		"input_length": len(remainder),
		"map_length":   map_length.Int(),
	}).Debug("Reading MappingValues")

	if remainder == nil || len(remainder) < 1 {
		log.WithFields(logrus.Fields{
			"at":     "(Mapping) Values",
			"reason": "data shorter than expected",
		}).Error("mapping contained no data")
		errs = []error{errors.New("mapping contained no data")}
		return
	}
	map_values := make(MappingValues, 0)
	int_map_length := map_length.Int()
	mapping_len := len(remainder)
	if mapping_len > int_map_length {
		log.WithFields(logrus.Fields{
			"at":                   "(Mapping) Values",
			"mapping_bytes_length": mapping_len,
			"mapping_length_field": int_map_length,
			"reason":               "data longer than expected",
		}).Warn("mapping format warning")
		errs = append(errs, errors.New("warning parsing mapping: data exists beyond length of mapping"))
	} else if int_map_length > mapping_len {
		log.WithFields(logrus.Fields{
			"at":                   "(Mapping) Values",
			"mapping_bytes_length": mapping_len,
			"mapping_length_field": int_map_length,
			"reason":               "data shorter than expected",
		}).Warn("mapping format warning")
		errs = append(errs, errors.New("warning parsing mapping: mapping length exceeds provided data"))
	}

	encounteredKeysMap := map[string]bool{}
	// pop off length bytes before parsing kv pairs
	// remainder = remainder[2:]

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
			log.WithFields(logrus.Fields{
				"at":     "(Mapping) Values",
				"reason": "mapping format violation",
			}).Warn("mapping format violation, too few bytes for a kv pair")
			break
		}

		key_str, more, err := ReadI2PString(remainder)
		if err != nil {
			if stopValueRead(err) {
				errs = append(errs, err)
				// return
			}
		}
		// overwriting remainder with more as another var to prevent memory weirdness in loops
		remainder = more
		// log.Printf("(MAPPING VALUES DEBUG) Remainder: %s\n", remainder)

		// Check if key has already been encountered in this mapping
		keyBytes, _ := key_str.Data()
		keyAsString := string(keyBytes)
		_, ok := encounteredKeysMap[keyAsString]
		if ok {
			log.WithFields(logrus.Fields{
				"at":     "(Mapping) Values",
				"reason": "duplicate key in mapping",
				"key":    string(key_str),
			}).Error("mapping format violation")
			log.Printf("DUPE: %s", key_str)
			errs = append(errs, errors.New("mapping format violation, duplicate key in mapping"))
			// Based on other implementations this does not seem to happen often?
			// Java throws an exception in this case, the base object is a Hashmap so the value is overwritten and an exception is thrown.
			// i2pd  as far as I can tell just overwrites the original value
			// Continue on, we can check if the Mapping contains duplicate keys later.
		}

		if !beginsWith(remainder, 0x3d) {
			log.WithFields(logrus.Fields{
				"at":     "(Mapping) Values",
				"reason": "expected =",
				"value:": string(remainder),
			}).Warn("mapping format violation")
			errs = append(errs, errors.New("mapping format violation, expected ="))
			log.Printf("ERRVAL: %s", remainder)
			break
		} else {
			remainder = remainder[1:]
		}

		// Read a value, breaking on fatal errors
		// and appending warnings
		val_str, more, err := ReadI2PString(remainder)
		if err != nil {
			if stopValueRead(err) {
				errs = append(errs, err)
				// return
			}
		}
		// overwriting remainder with more as another var to prevent memory weirdness in loops
		remainder = more
		// log.Printf("(MAPPING VALUES DEBUG) Remainder: %s\n", remainder)
		// log.Printf("(MAPPING VALUES DEBUG) String: value: %s", val_str)
		if !beginsWith(remainder, 0x3b) {
			log.WithFields(logrus.Fields{
				"at":     "(Mapping) Values",
				"reason": "expected ;",
				"value:": string(remainder),
			}).Warn("mapping format violation")
			errs = append(errs, errors.New("mapping format violation, expected ;"))
			break
		} else {
			remainder = remainder[1:]
		}

		// Append the key-value pair and break if there is no more data to read
		map_values = append(map_values, [2]I2PString{key_str, val_str})
		if len(remainder) == 0 {
			break
		}

		// Store the encountered key with arbitrary data
		encounteredKeysMap[keyAsString] = true
	}
	values = &map_values

	log.WithFields(logrus.Fields{
		"values_count":     len(map_values),
		"remainder_length": len(remainder_bytes),
		"error_count":      len(errs),
	}).Debug("Finished reading MappingValues")

	return
}
