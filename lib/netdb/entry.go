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

func (e *Entry) WriteTo(w io.Writer) (err error) {
	// Check if we have a RouterInfo to write
	if e.RouterInfo != nil {
		// Get the serialized bytes of the RouterInfo
		data, err := e.RouterInfo.Bytes()
		if err != nil {
			return fmt.Errorf("failed to serialize RouterInfo: %w", err)
		}
		// Check if the data is empty
		if len(data) == 0 {
			return fmt.Errorf("RouterInfo data is empty")
		}

		// Write the entry type indicator (1 for RouterInfo)
		if _, err = w.Write([]byte{1}); err != nil {
			return fmt.Errorf("failed to write entry type: %w", err)
		}

		// Write the length as a 2-byte big-endian value
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(len(data)))
		if _, err = w.Write(lenBytes); err != nil {
			return fmt.Errorf("failed to write length: %w", err)
		}

		// Write the actual RouterInfo data
		if _, err = w.Write(data); err != nil {
			return fmt.Errorf("failed to write RouterInfo data: %w", err)
		}

		return nil
	}

	// Check if we have a LeaseSet to write
	if e.LeaseSet != nil {
		// Get the serialized bytes of the LeaseSet
		data, err := e.LeaseSet.Bytes()

		// Write the entry type indicator (2 for LeaseSet)
		if _, err = w.Write([]byte{2}); err != nil {
			return fmt.Errorf("failed to write entry type: %w", err)
		}

		// Write the length as a 2-byte big-endian value
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(len(data)))
		if _, err = w.Write(lenBytes); err != nil {
			return fmt.Errorf("failed to write length: %w", err)
		}

		// Write the actual LeaseSet data
		if _, err = w.Write(data); err != nil {
			return fmt.Errorf("failed to write LeaseSet data: %w", err)
		}

		return nil
	}

	return fmt.Errorf("entry contains neither RouterInfo nor LeaseSet")
}

func (e *Entry) ReadFrom(r io.Reader) (err error) {
	// Read the entry type indicator
	typeBytes := make([]byte, 1)
	if _, err = r.Read(typeBytes); err != nil {
		return fmt.Errorf("failed to read entry type: %w", err)
	}

	// Read the length
	lenBytes := make([]byte, 2)
	if _, err = r.Read(lenBytes); err != nil {
		return fmt.Errorf("failed to read length: %w", err)
	}
	dataLen := binary.BigEndian.Uint16(lenBytes)

	// Read the entry data
	data := make([]byte, dataLen)
	if _, err = io.ReadFull(r, data); err != nil {
		return fmt.Errorf("failed to read entry data: %w", err)
	}

	// Process based on entry type
	switch typeBytes[0] {
	case 1: // RouterInfo
		ri, _, err := router_info.ReadRouterInfo(data)
		if err != nil {
			return fmt.Errorf("failed to parse RouterInfo: %w", err)
		}
		e.RouterInfo = &ri
		e.LeaseSet = nil

	case 2: // LeaseSet
		ls, err := lease_set.ReadLeaseSet(data)
		if err != nil {
			return fmt.Errorf("failed to parse LeaseSet: %w", err)
		}
		e.LeaseSet = &ls
		e.RouterInfo = nil

	default:
		return fmt.Errorf("unknown entry type: %d", typeBytes[0])
	}

	return nil
}
