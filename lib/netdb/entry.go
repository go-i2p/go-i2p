package netdb

import (
	"encoding/binary"
	"io"
	"reflect"

	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/common/meta_leaseset"
	"github.com/go-i2p/common/router_info"
	"github.com/samber/oops"
)

// File format type codes for local skiplist storage (Entry.WriteTo / Entry.ReadFrom).
//
// IMPORTANT: These differ from the DatabaseStore wire message type codes used in
// StdNetDB.Store and I2NP DatabaseStore messages:
//
//	Wire format (I2NP DatabaseStore):  File format (local skiplist):
//	  0 = RouterInfo                     1 = RouterInfo
//	  1 = LeaseSet                       2 = LeaseSet
//	  3 = LeaseSet2                      3 = LeaseSet2  (same)
//	  5 = EncryptedLeaseSet              5 = EncryptedLeaseSet  (same)
//	  7 = MetaLeaseSet                   7 = MetaLeaseSet  (same)
//
// The file format offsets RouterInfo and LeaseSet by +1 to avoid a zero type byte,
// which simplifies distinguishing valid entries from uninitialized data on disk.
const (
	FileTypeRouterInfo        = 1
	FileTypeLeaseSet          = 2
	FileTypeLeaseSet2         = 3
	FileTypeEncryptedLeaseSet = 5
	FileTypeMetaLeaseSet      = 7
)

// bytesSerializable is the interface for types that can serialize to bytes.
// All entry types (RouterInfo, LeaseSet, LeaseSet2, EncryptedLeaseSet, MetaLeaseSet) implement this.
type bytesSerializable interface {
	Bytes() ([]byte, error)
}

// entryTypeSpec holds metadata for each entry type in the dispatch table.
type entryTypeSpec struct {
	name     string                         // Human-readable name for logging
	typeCode byte                           // File format type code (e.g., FileTypeRouterInfo)
	getter   func(*Entry) bytesSerializable // Extracts the field from Entry
}

// Entry is a netdb entry that wraps a router info, lease set, lease set2, encrypted lease set, or meta lease set
// and provides serialization.
type Entry struct {
	*router_info.RouterInfo
	*lease_set.LeaseSet
	*lease_set2.LeaseSet2
	*encrypted_leaseset.EncryptedLeaseSet
	*meta_leaseset.MetaLeaseSet
}

// Serialize writes the Entry to the provided writer using a dispatch table approach.
func (e *Entry) Serialize(w io.Writer) error {
	log.WithField("at", "Entry.Serialize").Debug("Writing netdb entry")

	// Dispatch table: check each field type in order
	specs := []entryTypeSpec{
		{"RouterInfo", FileTypeRouterInfo, func(entry *Entry) bytesSerializable { return entry.RouterInfo }},
		{"LeaseSet", FileTypeLeaseSet, func(entry *Entry) bytesSerializable { return entry.LeaseSet }},
		{"LeaseSet2", FileTypeLeaseSet2, func(entry *Entry) bytesSerializable { return entry.LeaseSet2 }},
		{"EncryptedLeaseSet", FileTypeEncryptedLeaseSet, func(entry *Entry) bytesSerializable { return entry.EncryptedLeaseSet }},
		{"MetaLeaseSet", FileTypeMetaLeaseSet, func(entry *Entry) bytesSerializable { return entry.MetaLeaseSet }},
	}

	for _, spec := range specs {
		field := spec.getter(e)
		if !isNilSerializable(field) {
			log.WithField("type", spec.name).Debug("Writing entry")
			return e.serializeAndWrite(w, spec)
		}
	}

	log.WithField("at", "Entry.Serialize").Error("Entry contains no valid data")
	return oops.Errorf("entry contains no valid data (RouterInfo, LeaseSet, LeaseSet2, EncryptedLeaseSet, or MetaLeaseSet)")
}

// serializeAndWrite is the 3-step serialization pattern: serialize field → validate → write to output.
// Handles the common pattern used by all 5 entry types (RouterInfo, LeaseSet, LeaseSet2, EncryptedLeaseSet, MetaLeaseSet).
func (e *Entry) serializeAndWrite(w io.Writer, spec entryTypeSpec) error {
	// Step 1: Serialize the field to bytes
	field := spec.getter(e)
	data, err := field.Bytes()
	if err != nil {
		return oops.Errorf("failed to serialize %s: %w", spec.name, err)
	}

	// Step 2: Validate (special case: RouterInfo cannot be empty)
	if spec.name == "RouterInfo" && len(data) == 0 {
		return oops.Errorf("router info data empty")
	}

	// Step 3: Write to output with type indicator and length prefix
	return e.writeEntryData(w, spec.typeCode, data)
}

// writeEntryData writes entry data with type indicator and length prefix.
func (e *Entry) writeEntryData(w io.Writer, entryType byte, data []byte) error {
	if err := e.writeEntryType(w, entryType); err != nil {
		return err
	}

	if err := e.writeDataLength(w, len(data)); err != nil {
		return err
	}

	return e.writeData(w, data)
}

// isNilSerializable reports whether a bytesSerializable value is nil, including
// typed nil pointers stored inside the interface.
func isNilSerializable(field bytesSerializable) bool {
	if field == nil {
		return true
	}

	v := reflect.ValueOf(field)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map, reflect.Func, reflect.Chan:
		return v.IsNil()
	default:
		return false
	}
}

// writeEntryType writes the entry type indicator.
func (e *Entry) writeEntryType(w io.Writer, entryType byte) error {
	if _, err := w.Write([]byte{entryType}); err != nil {
		return oops.Errorf("failed to write entry type: %w", err)
	}
	return nil
}

// writeDataLength writes the data length as a 2-byte big-endian value.
// Returns an error if the data length exceeds the maximum representable
// by uint16 (65535 bytes).
func (e *Entry) writeDataLength(w io.Writer, length int) error {
	if length > 65535 {
		return oops.Errorf("entry data too large for uint16 length field: %d bytes (max 65535)", length)
	}
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(length))
	if _, err := w.Write(lenBytes); err != nil {
		return oops.Errorf("failed to write length: %w", err)
	}
	return nil
}

// writeData writes the actual entry data.
func (e *Entry) writeData(w io.Writer, data []byte) error {
	if _, err := w.Write(data); err != nil {
		return oops.Errorf("failed to write data: %w", err)
	}
	return nil
}

// Deserialize reads an Entry from the given reader, parsing the entry type indicator and data payload.
func (e *Entry) Deserialize(r io.Reader) (err error) {
	entryType, err := e.readEntryType(r)
	if err != nil {
		return err
	}

	data, err := e.readEntryData(r)
	if err != nil {
		return err
	}

	return e.processEntryData(entryType, data)
}

// readEntryType reads and returns the entry type indicator from the reader.
func (e *Entry) readEntryType(r io.Reader) (byte, error) {
	typeBytes := make([]byte, 1)
	if _, err := io.ReadFull(r, typeBytes); err != nil {
		return 0, oops.Errorf("failed to read entry type: %w", err)
	}
	return typeBytes[0], nil
}

// readEntryData reads the length and data from the reader.
func (e *Entry) readEntryData(r io.Reader) ([]byte, error) {
	dataLen, err := e.readDataLength(r)
	if err != nil {
		return nil, err
	}

	data := make([]byte, dataLen)
	if _, err = io.ReadFull(r, data); err != nil {
		return nil, oops.Errorf("failed to read entry data: %w", err)
	}

	return data, nil
}

// readDataLength reads and returns the data length from the reader.
func (e *Entry) readDataLength(r io.Reader) (uint16, error) {
	lenBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBytes); err != nil {
		return 0, oops.Errorf("failed to read length: %w", err)
	}
	return binary.BigEndian.Uint16(lenBytes), nil
}

// processEntryData processes the entry data based on the entry type.
func (e *Entry) processEntryData(entryType byte, data []byte) error {
	switch entryType {
	case FileTypeRouterInfo:
		return e.processRouterInfoData(data)
	case FileTypeLeaseSet:
		return e.processLeaseSetData(data)
	case FileTypeLeaseSet2:
		return e.processLeaseSet2Data(data)
	case FileTypeEncryptedLeaseSet:
		return e.processEncryptedLeaseSetData(data)
	case FileTypeMetaLeaseSet:
		return e.processMetaLeaseSetData(data)
	default:
		return oops.Errorf("unknown entry type: %d", entryType)
	}
}

// clearFields resets all entry fields to nil so that only one type is active at a time.
func (e *Entry) clearFields() {
	e.RouterInfo = nil
	e.LeaseSet = nil
	e.LeaseSet2 = nil
	e.EncryptedLeaseSet = nil
	e.MetaLeaseSet = nil
}

// processAndAssign is a generic helper for parsing entry data and assigning to the entry.
// It centralizes error handling, field clearing, and assignment for all entry types.
// The parser function should return the parsed data and error.
// The assigner function should assign the parsed data to the appropriate entry field.
func (e *Entry) processAndAssign(typeName string, data []byte,
	parser func([]byte) (interface{}, error),
	assigner func(interface{}),
) error {
	val, err := parser(data)
	if err != nil {
		return oops.Errorf("failed to parse %s: %w", typeName, err)
	}
	e.clearFields()
	assigner(val)
	return nil
}

// processRouterInfoData processes RouterInfo data and sets the entry.
func (e *Entry) processRouterInfoData(data []byte) error {
	return e.processAndAssign("RouterInfo", data,
		func(data []byte) (interface{}, error) {
			ri, _, err := router_info.ReadRouterInfo(data)
			return ri, err
		},
		func(val interface{}) {
			if ri, ok := val.(router_info.RouterInfo); ok {
				e.RouterInfo = &ri
			}
		})
}

// processLeaseSetData processes LeaseSet data and sets the entry.
func (e *Entry) processLeaseSetData(data []byte) error {
	return e.processAndAssign("LeaseSet", data,
		func(data []byte) (interface{}, error) {
			ls, err := lease_set.ReadLeaseSet(data)
			return ls, err
		},
		func(val interface{}) {
			if ls, ok := val.(lease_set.LeaseSet); ok {
				e.LeaseSet = &ls
			}
		})
}

// processLeaseSet2Data processes LeaseSet2 data and sets the entry.
func (e *Entry) processLeaseSet2Data(data []byte) error {
	return e.processAndAssign("LeaseSet2", data,
		func(data []byte) (interface{}, error) {
			ls2, _, err := lease_set2.ReadLeaseSet2(data)
			return ls2, err
		},
		func(val interface{}) {
			if ls2, ok := val.(lease_set2.LeaseSet2); ok {
				e.LeaseSet2 = &ls2
			}
		})
}

// processEncryptedLeaseSetData processes EncryptedLeaseSet data and sets the entry.
func (e *Entry) processEncryptedLeaseSetData(data []byte) error {
	return e.processAndAssign("EncryptedLeaseSet", data,
		func(data []byte) (interface{}, error) {
			els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(data)
			return els, err
		},
		func(val interface{}) {
			if els, ok := val.(encrypted_leaseset.EncryptedLeaseSet); ok {
				e.EncryptedLeaseSet = &els
			}
		})
}

// processMetaLeaseSetData processes MetaLeaseSet data and sets the entry.
func (e *Entry) processMetaLeaseSetData(data []byte) error {
	return e.processAndAssign("MetaLeaseSet", data,
		func(data []byte) (interface{}, error) {
			mls, _, err := meta_leaseset.ReadMetaLeaseSet(data)
			return mls, err
		},
		func(val interface{}) {
			if mls, ok := val.(meta_leaseset.MetaLeaseSet); ok {
				e.MetaLeaseSet = &mls
			}
		})
}
