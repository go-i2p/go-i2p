package i2cp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestHostLookupPayloadParse(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantID      uint32
		wantType    uint16
		wantQuery   string
		shouldError bool
	}{
		{
			name: "hash_lookup",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(12345))                      // RequestID
				binary.Write(buf, binary.BigEndian, uint16(HostLookupTypeHash))         // Type
				binary.Write(buf, binary.BigEndian, uint16(52))                         // Query length (base64 hash)
				buf.WriteString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // 52 char hash
				return buf.Bytes()
			}(),
			wantID:      12345,
			wantType:    HostLookupTypeHash,
			wantQuery:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			shouldError: false,
		},
		{
			name: "hostname_lookup",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(67890))
				binary.Write(buf, binary.BigEndian, uint16(HostLookupTypeHostname))
				hostname := "example.i2p"
				binary.Write(buf, binary.BigEndian, uint16(len(hostname)))
				buf.WriteString(hostname)
				return buf.Bytes()
			}(),
			wantID:      67890,
			wantType:    HostLookupTypeHostname,
			wantQuery:   "example.i2p",
			shouldError: false,
		},
		{
			name: "empty_query",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(99999))
				binary.Write(buf, binary.BigEndian, uint16(HostLookupTypeHostname))
				binary.Write(buf, binary.BigEndian, uint16(0)) // Empty query
				return buf.Bytes()
			}(),
			wantID:      99999,
			wantType:    HostLookupTypeHostname,
			wantQuery:   "",
			shouldError: false,
		},
		{
			name:        "too_short",
			data:        []byte{0x00, 0x01, 0x02}, // Only 3 bytes
			shouldError: true,
		},
		{
			name: "truncated_query",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(11111))
				binary.Write(buf, binary.BigEndian, uint16(HostLookupTypeHostname))
				binary.Write(buf, binary.BigEndian, uint16(100)) // Claims 100 bytes
				buf.WriteString("short")                         // Only 5 bytes
				return buf.Bytes()
			}(),
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := ParseHostLookupPayload(tt.data)

			if tt.shouldError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if payload.RequestID != tt.wantID {
				t.Errorf("RequestID = %d, want %d", payload.RequestID, tt.wantID)
			}

			if payload.LookupType != tt.wantType {
				t.Errorf("LookupType = %d, want %d", payload.LookupType, tt.wantType)
			}

			if payload.Query != tt.wantQuery {
				t.Errorf("Query = %q, want %q", payload.Query, tt.wantQuery)
			}
		})
	}
}

func TestHostLookupPayloadMarshal(t *testing.T) {
	tests := []struct {
		name    string
		payload *HostLookupPayload
		check   func([]byte) error
	}{
		{
			name: "hash_lookup",
			payload: &HostLookupPayload{
				RequestID:  54321,
				LookupType: HostLookupTypeHash,
				Query:      "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			},
			check: func(data []byte) error {
				if len(data) != 8+52 {
					t.Errorf("data length = %d, want %d", len(data), 8+52)
				}
				reqID := binary.BigEndian.Uint32(data[0:4])
				if reqID != 54321 {
					t.Errorf("RequestID = %d, want 54321", reqID)
				}
				lookupType := binary.BigEndian.Uint16(data[4:6])
				if lookupType != HostLookupTypeHash {
					t.Errorf("LookupType = %d, want %d", lookupType, HostLookupTypeHash)
				}
				queryLen := binary.BigEndian.Uint16(data[6:8])
				if queryLen != 52 {
					t.Errorf("QueryLength = %d, want 52", queryLen)
				}
				return nil
			},
		},
		{
			name: "hostname_lookup",
			payload: &HostLookupPayload{
				RequestID:  11111,
				LookupType: HostLookupTypeHostname,
				Query:      "test.i2p",
			},
			check: func(data []byte) error {
				if len(data) != 8+8 {
					t.Errorf("data length = %d, want 16", len(data))
				}
				lookupType := binary.BigEndian.Uint16(data[4:6])
				if lookupType != HostLookupTypeHostname {
					t.Errorf("LookupType = %d, want %d", lookupType, HostLookupTypeHostname)
				}
				query := string(data[8:])
				if query != "test.i2p" {
					t.Errorf("Query = %q, want %q", query, "test.i2p")
				}
				return nil
			},
		},
		{
			name: "empty_query",
			payload: &HostLookupPayload{
				RequestID:  0,
				LookupType: HostLookupTypeHostname,
				Query:      "",
			},
			check: func(data []byte) error {
				if len(data) != 8 {
					t.Errorf("data length = %d, want 8", len(data))
				}
				queryLen := binary.BigEndian.Uint16(data[6:8])
				if queryLen != 0 {
					t.Errorf("QueryLength = %d, want 0", queryLen)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error: %v", err)
			}

			if err := tt.check(data); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestHostLookupRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload *HostLookupPayload
	}{
		{
			name: "hash_lookup",
			payload: &HostLookupPayload{
				RequestID:  12345,
				LookupType: HostLookupTypeHash,
				Query:      "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
			},
		},
		{
			name: "hostname_lookup",
			payload: &HostLookupPayload{
				RequestID:  67890,
				LookupType: HostLookupTypeHostname,
				Query:      "example.i2p",
			},
		},
		{
			name: "long_hostname",
			payload: &HostLookupPayload{
				RequestID:  99999,
				LookupType: HostLookupTypeHostname,
				Query:      "very-long-hostname-that-tests-longer-queries.i2p",
			},
		},
		{
			name: "empty_query",
			payload: &HostLookupPayload{
				RequestID:  0,
				LookupType: HostLookupTypeHash,
				Query:      "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error: %v", err)
			}

			parsed, err := ParseHostLookupPayload(data)
			if err != nil {
				t.Fatalf("ParseHostLookupPayload() error: %v", err)
			}

			if parsed.RequestID != tt.payload.RequestID {
				t.Errorf("RequestID = %d, want %d", parsed.RequestID, tt.payload.RequestID)
			}

			if parsed.LookupType != tt.payload.LookupType {
				t.Errorf("LookupType = %d, want %d", parsed.LookupType, tt.payload.LookupType)
			}

			if parsed.Query != tt.payload.Query {
				t.Errorf("Query = %q, want %q", parsed.Query, tt.payload.Query)
			}
		})
	}
}

func TestHostReplyPayloadParse(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantID      uint32
		wantCode    uint8
		wantDestLen int
		shouldError bool
	}{
		{
			name: "success_with_destination",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(12345))
				buf.WriteByte(HostReplySuccess)
				buf.Write(make([]byte, 387)) // Standard destination size
				return buf.Bytes()
			}(),
			wantID:      12345,
			wantCode:    HostReplySuccess,
			wantDestLen: 387,
			shouldError: false,
		},
		{
			name: "not_found",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(67890))
				buf.WriteByte(HostReplyNotFound)
				return buf.Bytes()
			}(),
			wantID:      67890,
			wantCode:    HostReplyNotFound,
			wantDestLen: 0,
			shouldError: false,
		},
		{
			name: "timeout",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(11111))
				buf.WriteByte(HostReplyTimeout)
				return buf.Bytes()
			}(),
			wantID:      11111,
			wantCode:    HostReplyTimeout,
			wantDestLen: 0,
			shouldError: false,
		},
		{
			name: "error",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(99999))
				buf.WriteByte(HostReplyError)
				return buf.Bytes()
			}(),
			wantID:      99999,
			wantCode:    HostReplyError,
			wantDestLen: 0,
			shouldError: false,
		},
		{
			name:        "too_short",
			data:        []byte{0x00, 0x01, 0x02}, // Only 3 bytes
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := ParseHostReplyPayload(tt.data)

			if tt.shouldError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if payload.RequestID != tt.wantID {
				t.Errorf("RequestID = %d, want %d", payload.RequestID, tt.wantID)
			}

			if payload.ResultCode != tt.wantCode {
				t.Errorf("ResultCode = %d, want %d", payload.ResultCode, tt.wantCode)
			}

			if len(payload.Destination) != tt.wantDestLen {
				t.Errorf("Destination length = %d, want %d", len(payload.Destination), tt.wantDestLen)
			}
		})
	}
}

func TestHostReplyPayloadMarshal(t *testing.T) {
	tests := []struct {
		name    string
		payload *HostReplyPayload
		check   func([]byte) error
	}{
		{
			name: "success_with_destination",
			payload: &HostReplyPayload{
				RequestID:   54321,
				ResultCode:  HostReplySuccess,
				Destination: make([]byte, 387),
			},
			check: func(data []byte) error {
				if len(data) != 5+387 {
					t.Errorf("data length = %d, want %d", len(data), 5+387)
				}
				reqID := binary.BigEndian.Uint32(data[0:4])
				if reqID != 54321 {
					t.Errorf("RequestID = %d, want 54321", reqID)
				}
				resultCode := data[4]
				if resultCode != HostReplySuccess {
					t.Errorf("ResultCode = %d, want %d", resultCode, HostReplySuccess)
				}
				return nil
			},
		},
		{
			name: "not_found",
			payload: &HostReplyPayload{
				RequestID:   11111,
				ResultCode:  HostReplyNotFound,
				Destination: nil,
			},
			check: func(data []byte) error {
				if len(data) != 5 {
					t.Errorf("data length = %d, want 5", len(data))
				}
				resultCode := data[4]
				if resultCode != HostReplyNotFound {
					t.Errorf("ResultCode = %d, want %d", resultCode, HostReplyNotFound)
				}
				return nil
			},
		},
		{
			name: "timeout",
			payload: &HostReplyPayload{
				RequestID:   22222,
				ResultCode:  HostReplyTimeout,
				Destination: []byte{}, // Empty slice
			},
			check: func(data []byte) error {
				if len(data) != 5 {
					t.Errorf("data length = %d, want 5", len(data))
				}
				resultCode := data[4]
				if resultCode != HostReplyTimeout {
					t.Errorf("ResultCode = %d, want %d", resultCode, HostReplyTimeout)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error: %v", err)
			}

			if err := tt.check(data); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestHostReplyRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload *HostReplyPayload
	}{
		{
			name: "success_with_destination",
			payload: &HostReplyPayload{
				RequestID:   12345,
				ResultCode:  HostReplySuccess,
				Destination: make([]byte, 387),
			},
		},
		{
			name: "not_found",
			payload: &HostReplyPayload{
				RequestID:   67890,
				ResultCode:  HostReplyNotFound,
				Destination: nil,
			},
		},
		{
			name: "timeout",
			payload: &HostReplyPayload{
				RequestID:   11111,
				ResultCode:  HostReplyTimeout,
				Destination: []byte{},
			},
		},
		{
			name: "error",
			payload: &HostReplyPayload{
				RequestID:   99999,
				ResultCode:  HostReplyError,
				Destination: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error: %v", err)
			}

			parsed, err := ParseHostReplyPayload(data)
			if err != nil {
				t.Fatalf("ParseHostReplyPayload() error: %v", err)
			}

			if parsed.RequestID != tt.payload.RequestID {
				t.Errorf("RequestID = %d, want %d", parsed.RequestID, tt.payload.RequestID)
			}

			if parsed.ResultCode != tt.payload.ResultCode {
				t.Errorf("ResultCode = %d, want %d", parsed.ResultCode, tt.payload.ResultCode)
			}

			if len(parsed.Destination) != len(tt.payload.Destination) {
				t.Errorf("Destination length = %d, want %d",
					len(parsed.Destination), len(tt.payload.Destination))
			}
		})
	}
}

func TestHostLookupConstants(t *testing.T) {
	// Verify lookup type constants
	if HostLookupTypeHash != 0 {
		t.Errorf("HostLookupTypeHash = %d, want 0", HostLookupTypeHash)
	}
	if HostLookupTypeHostname != 1 {
		t.Errorf("HostLookupTypeHostname = %d, want 1", HostLookupTypeHostname)
	}

	// Verify result code constants
	if HostReplySuccess != 0 {
		t.Errorf("HostReplySuccess = %d, want 0", HostReplySuccess)
	}
	if HostReplyNotFound != 1 {
		t.Errorf("HostReplyNotFound = %d, want 1", HostReplyNotFound)
	}
	if HostReplyTimeout != 2 {
		t.Errorf("HostReplyTimeout = %d, want 2", HostReplyTimeout)
	}
	if HostReplyError != 3 {
		t.Errorf("HostReplyError = %d, want 3", HostReplyError)
	}
}

func TestHostLookupTypeNames(t *testing.T) {
	// Verify message type constants
	if MessageTypeHostLookup != 38 {
		t.Errorf("MessageTypeHostLookup = %d, want 38", MessageTypeHostLookup)
	}
	if MessageTypeHostReply != 39 {
		t.Errorf("MessageTypeHostReply = %d, want 39", MessageTypeHostReply)
	}

	// Verify message type names
	if name := MessageTypeName(MessageTypeHostLookup); name != "HostLookup" {
		t.Errorf("MessageTypeName(HostLookup) = %q, want %q", name, "HostLookup")
	}
	if name := MessageTypeName(MessageTypeHostReply); name != "HostReply" {
		t.Errorf("MessageTypeName(HostReply) = %q, want %q", name, "HostReply")
	}

	// Verify deprecated types are distinct
	if MessageTypeHostLookupDeprecated != 13 {
		t.Errorf("MessageTypeHostLookupDeprecated = %d, want 13", MessageTypeHostLookupDeprecated)
	}
	if MessageTypeHostReplyDeprecated != 14 {
		t.Errorf("MessageTypeHostReplyDeprecated = %d, want 14", MessageTypeHostReplyDeprecated)
	}
}
