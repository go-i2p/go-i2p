package i2np

// ParseInboundShortI2NP deserializes an I2NP message from the 9-byte short
// header used by NTCP2 and SSU2 data-phase blocks, producing the concrete
// typed message when the message type's handler asserts a typed carrier.
//
// The transport layer previously always produced a bare *BaseI2NPMessage.
// That satisfies DataCarrier (GetData) but not the typed carrier interfaces
// (TunnelCarrier, PayloadCarrier), so the processor's typed assertions in
// processTunnelDataMessage (type 18) and processDataMessage (type 20) failed
// with "message does not implement ... interface" and the message was dropped.
//
// This factory parses the short header into a base message, then — for the
// message types whose handlers require a typed carrier — re-wraps the base in
// the concrete typed message and populates its accessors from the body. The
// typed message embeds the same base, so all Message behavior (Type, MessageID,
// Expiration, MarshalBinary) is unchanged; only the typed accessors are added.
//
// Every other message type is returned as the base *BaseI2NPMessage, which
// already satisfies DataCarrier — sufficient for DatabaseStore (1),
// DatabaseSearchReply (3), Garlic (11) and the tunnel-build types (23/25/26),
// all of which coerce through DataCarrier rather than asserting a typed carrier.
//
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst).
func ParseInboundShortI2NP(data []byte) (Message, error) {
	base := &BaseI2NPMessage{}
	if err := base.UnmarshalShortI2NP(data); err != nil {
		return nil, err
	}
	return promoteInboundMessage(base), nil
}

// promoteInboundMessage re-wraps an already-header-parsed base message in the
// concrete typed message whose handler asserts a typed carrier. It is split out
// from ParseInboundShortI2NP so the standard-header inbound path can reuse it.
//
// On a body that cannot be parsed for the declared type (e.g. a malformed
// TunnelData body), the original base is returned unchanged rather than an
// error: the downstream handler will then reject it on the carrier assertion or
// size check exactly as before, so a malformed message never becomes a hard
// parse failure at the transport boundary.
func promoteInboundMessage(base *BaseI2NPMessage) Message {
	switch base.type_ {
	case I2NPMessageTypeTunnelData:
		td := &TunnelDataMessage{BaseI2NPMessage: base}
		if err := td.parseBody(base.data); err != nil {
			return base
		}
		return td
	case I2NPMessageTypeData:
		dm := &DataMessage{BaseI2NPMessage: base}
		if err := dm.parseBody(base.data); err != nil {
			return base
		}
		return dm
	default:
		return base
	}
}

// ParseInboundStandardI2NP deserializes an I2NP message from the 16-byte
// standard header (used for tunnel-delivered I2NP inside TunnelGateway and
// garlic cloves) and applies the same typed-carrier promotion as
// [ParseInboundShortI2NP]. This keeps the promotion consistent across every
// inbound parse path so the typed-carrier class of bug cannot reappear on a
// different header format.
func ParseInboundStandardI2NP(data []byte) (Message, error) {
	base := &BaseI2NPMessage{}
	if err := base.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return promoteInboundMessage(base), nil
}

// Compile-time guarantees that the promoted types satisfy the carrier
// interfaces their handlers assert. These mirror the assertions in
// processTunnelDataMessage and processDataMessage.
var (
	_ TunnelCarrier  = (*TunnelDataMessage)(nil)
	_ PayloadCarrier = (*DataMessage)(nil)
	_ Message        = (*TunnelDataMessage)(nil)
	_ Message        = (*DataMessage)(nil)
)
