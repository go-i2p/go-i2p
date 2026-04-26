package netdb

import (
	"encoding/binary"
	"io"

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

// Entry is a netdb entry that wraps a router info, lease set, lease set2, encrypted lease set, or meta lease set
// and provides serialization.
type Entry struct {
	*router_info.RouterInfo
	*lease_set.LeaseSet
	*lease_set2.LeaseSet2
	*encrypted_leaseset.EncryptedLeaseSet
	*meta_leaseset.MetaLeaseSet
}

// Serialize writes the Entry to the provided writer.
func (e *Entry) Serialize(w io.Writer) error {
	log.WithField("at", "Entry.Serialize").Debug("Writing netdb entry")

	if e.RouterInfo != nil {
		log.WithField("type", "RouterInfo").Debug("Writing RouterInfo entry")
		return e.writeRouterInfo(w)
	}

	if e.LeaseSet != nil {
		log.WithField("type", "LeaseSet").Debug("Writing LeaseSet entry")
		return e.writeLeaseSet(w)
	}

	if e.LeaseSet2 != nil {
		log.WithField("type", "LeaseSet2").Debug("Writing LeaseSet2 entry")
		return e.writeLeaseSet2(w)
	}

	if e.EncryptedLeaseSet != nil {
		log.WithField("type", "EncryptedLeaseSet").Debug("Writing EncryptedLeaseSet entry")
		return e.writeEncryptedLeaseSet(w)
	}

	if e.MetaLeaseSet != nil {
		log.WithField("type", "MetaLeaseSet").Debug("Writing MetaLeaseSet entry")
		return e.writeMetaLeaseSet(w)
	}

	log.WithField("at", "Entry.Serialize").Error("Entry contains no valid data")
	return oops.Errorf("entry contains no valid data (RouterInfo, LeaseSet, LeaseSet2, EncryptedLeaseSet, or MetaLeaseSet)")
}

// writeRouterInfo writes a RouterInfo entry to the writer.
func (e *Entry) writeRouterInfo(w io.Writer) error {
	data, err := e.serializeRouterInfo()
	if err != nil {
		return err
	}

	return e.writeEntryData(w, FileTypeRouterInfo, data)
}

// writeLeaseSet writes a LeaseSet entry to the writer.
func (e *Entry) writeLeaseSet(w io.Writer) error {
	data, err := e.serializeLeaseSet()
	if err != nil {
		return err
	}

	return e.writeEntryData(w, FileTypeLeaseSet, data)
}

// writeLeaseSet2 writes a LeaseSet2 entry to the writer.
func (e *Entry) writeLeaseSet2(w io.Writer) error {
	data, err := e.serializeLeaseSet2()
	if err != nil {
		return err
	}

	return e.writeEntryData(w, FileTypeLeaseSet2, data)
}

// writeEncryptedLeaseSet writes an EncryptedLeaseSet entry to the writer.
func (e *Entry) writeEncryptedLeaseSet(w io.Writer) error {
	data, err := e.serializeEncryptedLeaseSet()
	if err != nil {
		return err
	}

	return e.writeEntryData(w, FileTypeEncryptedLeaseSet, data)
}

// writeMetaLeaseSet writes a MetaLeaseSet entry to the writer.
func (e *Entry) writeMetaLeaseSet(w io.Writer) error {
	data, err := e.serializeMetaLeaseSet()
	if err != nil {
		return err
	}

	return e.writeEntryData(w, FileTypeMetaLeaseSet, data)
}

// serializeRouterInfo serializes the RouterInfo and validates the result.
func (e *Entry) serializeRouterInfo() ([]byte, error) {
	data, err := e.RouterInfo.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize RouterInfo: %w", err)
	}

	if len(data) == 0 {
		return nil, oops.Errorf("router info data empty")
	}

	return data, nil
}

// serializeLeaseSet serializes the LeaseSet and validates the result.
func (e *Entry) serializeLeaseSet() ([]byte, error) {
	data, err := e.LeaseSet.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize LeaseSet: %w", err)
	}

	return data, nil
}

// serializeLeaseSet2 serializes the LeaseSet2 and validates the result.
func (e *Entry) serializeLeaseSet2() ([]byte, error) {
	data, err := e.LeaseSet2.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize LeaseSet2: %w", err)
	}

	return data, nil
}

// serializeEncryptedLeaseSet serializes the EncryptedLeaseSet and validates the result.
func (e *Entry) serializeEncryptedLeaseSet() ([]byte, error) {
	data, err := e.EncryptedLeaseSet.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize EncryptedLeaseSet: %w", err)
	}

	return data, nil
}

// serializeMetaLeaseSet serializes the MetaLeaseSet and validates the result.
func (e *Entry) serializeMetaLeaseSet() ([]byte, error) {
	data, err := e.MetaLeaseSet.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize MetaLeaseSet: %w", err)
	}

	return data, nil
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

// processRouterInfoData processes RouterInfo data and sets the entry.
func (e *Entry) processRouterInfoData(data []byte) error {
	ri, _, err := router_info.ReadRouterInfo(data)
	if err != nil {
		return oops.Errorf("failed to parse RouterInfo: %w", err)
	}
	e.clearFields()
	e.RouterInfo = &ri
	return nil
}

// processLeaseSetData processes LeaseSet data and sets the entry.
func (e *Entry) processLeaseSetData(data []byte) error {
	ls, err := lease_set.ReadLeaseSet(data)
	if err != nil {
		return oops.Errorf("failed to parse LeaseSet: %w", err)
	}
	e.clearFields()
	e.LeaseSet = &ls
	return nil
}

// processLeaseSet2Data processes LeaseSet2 data and sets the entry.
func (e *Entry) processLeaseSet2Data(data []byte) error {
	ls2, _, err := lease_set2.ReadLeaseSet2(data)
	if err != nil {
		return oops.Errorf("failed to parse LeaseSet2: %w", err)
	}
	e.clearFields()
	e.LeaseSet2 = &ls2
	return nil
}

// processEncryptedLeaseSetData processes EncryptedLeaseSet data and sets the entry.
func (e *Entry) processEncryptedLeaseSetData(data []byte) error {
	els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(data)
	if err != nil {
		return oops.Errorf("failed to parse EncryptedLeaseSet: %w", err)
	}
	e.clearFields()
	e.EncryptedLeaseSet = &els
	return nil
}

// processMetaLeaseSetData processes MetaLeaseSet data and sets the entry.
func (e *Entry) processMetaLeaseSetData(data []byte) error {
	mls, _, err := meta_leaseset.ReadMetaLeaseSet(data)
	if err != nil {
		return oops.Errorf("failed to parse MetaLeaseSet: %w", err)
	}
	e.clearFields()
	e.MetaLeaseSet = &mls
	return nil
}
