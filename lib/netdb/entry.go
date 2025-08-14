package netdb

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
)

// netdb entry
// wraps a router info and provides serialization
type Entry struct {
	*router_info.RouterInfo
	*lease_set.LeaseSet
}

// WriteTo writes the Entry to the provided writer.
func (e *Entry) WriteTo(w io.Writer) error {
	if e.RouterInfo != nil {
		return e.writeRouterInfo(w)
	}

	if e.LeaseSet != nil {
		return e.writeLeaseSet(w)
	}

	return fmt.Errorf("entry contains neither RouterInfo nor LeaseSet")
}

// writeRouterInfo writes a RouterInfo entry to the writer.
func (e *Entry) writeRouterInfo(w io.Writer) error {
	data, err := e.serializeRouterInfo()
	if err != nil {
		return err
	}

	return e.writeEntryData(w, 1, data)
}

// writeLeaseSet writes a LeaseSet entry to the writer.
func (e *Entry) writeLeaseSet(w io.Writer) error {
	data, err := e.serializeLeaseSet()
	if err != nil {
		return err
	}

	return e.writeEntryData(w, 2, data)
}

// serializeRouterInfo serializes the RouterInfo and validates the result.
func (e *Entry) serializeRouterInfo() ([]byte, error) {
	data, err := e.RouterInfo.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize RouterInfo: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("RouterInfo data is empty")
	}

	return data, nil
}

// serializeLeaseSet serializes the LeaseSet and validates the result.
func (e *Entry) serializeLeaseSet() ([]byte, error) {
	data, err := e.LeaseSet.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize LeaseSet: %w", err)
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
		return fmt.Errorf("failed to write entry type: %w", err)
	}
	return nil
}

// writeDataLength writes the data length as a 2-byte big-endian value.
func (e *Entry) writeDataLength(w io.Writer, length int) error {
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(length))
	if _, err := w.Write(lenBytes); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}
	return nil
}

// writeData writes the actual entry data.
func (e *Entry) writeData(w io.Writer, data []byte) error {
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}
	return nil
}

func (e *Entry) ReadFrom(r io.Reader) (err error) {
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
	if _, err := r.Read(typeBytes); err != nil {
		return 0, fmt.Errorf("failed to read entry type: %w", err)
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
		return nil, fmt.Errorf("failed to read entry data: %w", err)
	}

	return data, nil
}

// readDataLength reads and returns the data length from the reader.
func (e *Entry) readDataLength(r io.Reader) (uint16, error) {
	lenBytes := make([]byte, 2)
	if _, err := r.Read(lenBytes); err != nil {
		return 0, fmt.Errorf("failed to read length: %w", err)
	}
	return binary.BigEndian.Uint16(lenBytes), nil
}

// processEntryData processes the entry data based on the entry type.
func (e *Entry) processEntryData(entryType byte, data []byte) error {
	switch entryType {
	case 1: // RouterInfo
		return e.processRouterInfoData(data)
	case 2: // LeaseSet
		return e.processLeaseSetData(data)
	default:
		return fmt.Errorf("unknown entry type: %d", entryType)
	}
}

// processRouterInfoData processes RouterInfo data and sets the entry.
func (e *Entry) processRouterInfoData(data []byte) error {
	ri, _, err := router_info.ReadRouterInfo(data)
	if err != nil {
		return fmt.Errorf("failed to parse RouterInfo: %w", err)
	}
	e.RouterInfo = &ri
	e.LeaseSet = nil
	return nil
}

// processLeaseSetData processes LeaseSet data and sets the entry.
func (e *Entry) processLeaseSetData(data []byte) error {
	ls, err := lease_set.ReadLeaseSet(data)
	if err != nil {
		return fmt.Errorf("failed to parse LeaseSet: %w", err)
	}
	e.LeaseSet = &ls
	e.RouterInfo = nil
	return nil
}
