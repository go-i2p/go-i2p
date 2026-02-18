package ntcp2

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Options represents the NTCP2 options block parameters used for negotiating
// padding and traffic shaping between peers.
//
// Spec reference: https://geti2p.net/spec/ntcp2#options-block
//
// The options block is sent in message 3 part 2 (first post-handshake payload
// from the initiator) and can be resent during the data phase to renegotiate
// parameters.
type Options struct {
	// Version is the NTCP2 protocol version. Currently 0.
	Version uint8

	// PaddingMin is the minimum padding length for data-phase frames.
	// Encoded as a 4.4 fixed-point ratio of the frame payload size.
	PaddingMin float64

	// PaddingMax is the maximum padding length for data-phase frames.
	// Encoded as a 4.4 fixed-point ratio of the frame payload size.
	PaddingMax float64

	// DummyMin is the minimum interval (in seconds) between dummy traffic frames.
	// 0 means no dummy traffic.
	DummyMin uint16

	// DummyMax is the maximum interval (in seconds) between dummy traffic frames.
	// 0 means no dummy traffic.
	DummyMax uint16

	// DelayMin is the minimum intra-message delay (in milliseconds).
	// 0 means no artificial delay.
	DelayMin uint16

	// DelayMax is the maximum intra-message delay (in milliseconds).
	// 0 means no artificial delay.
	DelayMax uint16
}

// optionsBlockMinSize is the minimum size of a serialized options block.
// Version(1) + PaddingMin(1) + PaddingMax(1) + DummyMin(2) + DummyMax(2) +
// DelayMin(2) + DelayMax(2) = 11 bytes.
const optionsBlockMinSize = 11

// DefaultOptions returns the default NTCP2 options with no padding limits,
// no dummy traffic, and no delay. This is the most permissive configuration.
func DefaultOptions() *Options {
	return &Options{
		Version:    0,
		PaddingMin: 0,
		PaddingMax: 0,
		DummyMin:   0,
		DummyMax:   0,
		DelayMin:   0,
		DelayMax:   0,
	}
}

// ParseOptions parses an options block payload (the data portion, without
// the 3-byte block header) into an Options struct.
func ParseOptions(data []byte) (*Options, error) {
	if len(data) < optionsBlockMinSize {
		return nil, fmt.Errorf("options block too short: %d bytes, need at least %d", len(data), optionsBlockMinSize)
	}

	opts := &Options{
		Version:    data[0],
		PaddingMin: decodeFixed44(data[1]),
		PaddingMax: decodeFixed44(data[2]),
		DummyMin:   binary.BigEndian.Uint16(data[3:5]),
		DummyMax:   binary.BigEndian.Uint16(data[5:7]),
		DelayMin:   binary.BigEndian.Uint16(data[7:9]),
		DelayMax:   binary.BigEndian.Uint16(data[9:11]),
	}

	return opts, nil
}

// Serialize encodes the Options into a byte slice suitable for use as the
// data portion of an Options block (type 1).
func (o *Options) Serialize() []byte {
	data := make([]byte, optionsBlockMinSize)
	data[0] = o.Version
	data[1] = encodeFixed44(o.PaddingMin)
	data[2] = encodeFixed44(o.PaddingMax)
	binary.BigEndian.PutUint16(data[3:5], o.DummyMin)
	binary.BigEndian.PutUint16(data[5:7], o.DummyMax)
	binary.BigEndian.PutUint16(data[7:9], o.DelayMin)
	binary.BigEndian.PutUint16(data[9:11], o.DelayMax)
	return data
}

// NewOptionsBlock creates an Options block (type 1) from an Options struct.
func NewOptionsBlock(opts *Options) Block {
	return Block{Type: BlockTypeOptions, Data: opts.Serialize()}
}

// decodeFixed44 decodes a 4.4 fixed-point byte into a float64.
// The high nibble is the integer part, the low nibble is the fractional part.
// Range: 0.0 to 15.9375 (15 + 15/16).
func decodeFixed44(b byte) float64 {
	integer := float64(b >> 4)
	fraction := float64(b&0x0F) / 16.0
	return integer + fraction
}

// encodeFixed44 encodes a float64 into a 4.4 fixed-point byte.
// Values are clamped to the representable range [0, 15.9375].
func encodeFixed44(v float64) byte {
	if v < 0 {
		v = 0
	}
	if v > 15.9375 {
		v = 15.9375
	}
	integer := byte(math.Floor(v))
	fraction := byte(math.Round((v - math.Floor(v)) * 16))
	if fraction > 15 {
		fraction = 15
	}
	return (integer << 4) | (fraction & 0x0F)
}
