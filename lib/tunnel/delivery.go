package tunnel

import (
	"encoding/binary"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

/*
I2P First Fragment Delivery Instructions
https://geti2p.net/spec/tunnel-message#struct-tunnelmessagedeliveryinstructions
Accurate for version 0.9.11

+----+----+----+----+----+----+----+----+
|flag|  Tunnel ID (opt)  |              |
+----+----+----+----+----+              +
|                                       |
+                                       +
|         To Hash (optional)            |
+                                       +
|                                       |
+                        +--------------+
|                        |dly | Message
+----+----+----+----+----+----+----+----+
 ID (opt) |extended opts (opt)|  size   |
+----+----+----+----+----+----+----+----+

flag ::
       1 byte
       Bit order: 76543210
       bit 7: 0 to specify an initial fragment or an unfragmented message
       bits 6-5: delivery type
                 0x0 = LOCAL
                 0x01 = TUNNEL
                 0x02 = ROUTER
                 0x03 = unused, invalid
                 Note: LOCAL is used for inbound tunnels only, unimplemented
                 for outbound tunnels
       bit 4: delay included?  Unimplemented, always 0
                               If 1, a delay byte is included
       bit 3: fragmented?  If 0, the message is not fragmented, what follows
                           is the entire message
                           If 1, the message is fragmented, and the
                           instructions contain a Message ID
       bit 2: extended options?  Unimplemented, always 0
                                 If 1, extended options are included
       bits 1-0: reserved, set to 0 for compatibility with future uses

Tunnel ID :: TunnelId
       4 bytes
       Optional, present if delivery type is TUNNEL
       The destination tunnel ID

To Hash ::
       32 bytes
       Optional, present if delivery type is ROUTER, or TUNNEL			See: https://trac.i2p2.de/ticket/1845#ticket
          If ROUTER, the SHA256 Hash of the router
          If TUNNEL, the SHA256 Hash of the gateway router

Delay ::
       1 byte
       Optional, present if delay included flag is set
       In tunnel messages: Unimplemented, never present; original
       specification:
          bit 7: type (0 = strict, 1 = randomized)
          bits 6-0: delay exponent (2^value minutes)

Message ID ::
       4 bytes
       Optional, present if this message is the first of 2 or more fragments
          (i.e. if the fragmented bit is 1)
       An ID that uniquely identifies all fragments as belonging to a single
       message (the current implementation uses I2NPMessageHeader.msg_id)

Extended Options ::
       2 or more bytes
       Optional, present if extend options flag is set
       Unimplemented, never present; original specification:
       One byte length and then that many bytes

size ::
       2 bytes
       The length of the fragment that follows
       Valid values: 1 to approx. 960 in a tunnel message

Total length: Typical length is:
       3 bytes for LOCAL delivery (tunnel message);
       35 bytes for ROUTER / DESTINATION delivery or 39 bytes for TUNNEL
       delivery (unfragmented tunnel message);
       39 bytes for ROUTER delivery or 43 bytes for TUNNEL delivery (first
       fragment)



I2P Follow-on Fragment Delivery Instructions
https://geti2p.net/spec/tunnel-message#struct-tunnelmessagedeliveryinstructions
Accurate for version 0.9.11

----+----+----+----+----+----+----+
|frag|     Message ID    |  size   |
+----+----+----+----+----+----+----+

frag ::
       1 byte
       Bit order: 76543210
       binary 1nnnnnnd
              bit 7: 1 to indicate this is a follow-on fragment
              bits 6-1: nnnnnn is the 6 bit fragment number from 1 to 63
              bit 0: d is 1 to indicate the last fragment, 0 otherwise

Message ID ::
       4 bytes
       Identifies the fragment sequence that this fragment belongs to.
       This will match the message ID of an initial fragment (a fragment
       with flag bit 7 set to 0 and flag bit 3 set to 1).

size ::
       2 bytes
       the length of the fragment that follows
       valid values: 1 to 996

total length: 7 bytes
*/

const (
	DT_LOCAL = iota
	DT_TUNNEL
	DT_ROUTER
	DT_UNUSED
)

const (
	FIRST_FRAGMENT = iota
	FOLLOW_ON_FRAGMENT
)

const (
	FLAG_SIZE                 = 1
	TUNNEL_ID_SIZE            = 4
	HASH_SIZE                 = 32
	DELAY_SIZE                = 1
	MESSAGE_ID_SIZE           = 4
	EXTENDED_OPTIONS_MIN_SIZE = 2
	SIZE_FIELD_SIZE           = 2
)

type DelayFactor byte

// DeliveryInstructions represents I2P tunnel message delivery instructions
type DeliveryInstructions struct {
	// Type: FIRST_FRAGMENT or FOLLOW_ON_FRAGMENT
	fragmentType int

	// For FIRST_FRAGMENT
	deliveryType  byte // DT_LOCAL, DT_TUNNEL, DT_ROUTER
	hasDelay      bool
	fragmented    bool
	hasExtOptions bool
	tunnelID      uint32      // Present if deliveryType == DT_TUNNEL
	hash          common.Hash // Present if deliveryType == DT_TUNNEL or DT_ROUTER
	delay         DelayFactor // Present if hasDelay
	messageID     uint32      // Present if fragmented
	extendedOpts  []byte      // Present if hasExtOptions
	fragmentSize  uint16

	// For FOLLOW_ON_FRAGMENT
	fragmentNumber int
	lastFragment   bool
	// messageID and fragmentSize also used for FOLLOW_ON_FRAGMENT
}

// NewDeliveryInstructions creates a new DeliveryInstructions from raw bytes
func NewDeliveryInstructions(bytes []byte) (*DeliveryInstructions, error) {
	di, _, err := readDeliveryInstructionsStruct(bytes)
	return di, err
}

// Bytes serializes the DeliveryInstructions to bytes
func (di *DeliveryInstructions) Bytes() ([]byte, error) {
	if di == nil {
		return nil, oops.Errorf("cannot serialize nil DeliveryInstructions")
	}

	if di.fragmentType == FOLLOW_ON_FRAGMENT {
		return di.serializeFollowOnFragment()
	}
	return di.serializeFirstFragment()
}

// parseFollowOnFragment reads a follow-on fragment delivery instruction from the provided data.
// It extracts the fragment number, last fragment flag, message ID, and fragment size.
// Returns the parsed DeliveryInstructions and the number of bytes consumed.
func parseFollowOnFragment(data []byte, flag byte) (*DeliveryInstructions, int, error) {
	di := &DeliveryInstructions{}
	di.fragmentType = FOLLOW_ON_FRAGMENT
	di.fragmentNumber = int((flag & 0x7e) >> 1)
	di.lastFragment = (flag & 0x01) == 0x01

	if len(data) < 7 {
		return nil, 0, oops.Errorf("insufficient data for FOLLOW_ON_FRAGMENT")
	}

	di.messageID = binary.BigEndian.Uint32(data[1:5])
	di.fragmentSize = binary.BigEndian.Uint16(data[5:7])
	return di, 7, nil
}

// parseFirstFragmentFlags extracts delivery type and feature flags from the first fragment flag byte.
func parseFirstFragmentFlags(di *DeliveryInstructions, flag byte) {
	di.fragmentType = FIRST_FRAGMENT
	di.deliveryType = (flag & 0x60) >> 5     // bits 6-5
	di.hasDelay = (flag & 0x10) == 0x10      // bit 4
	di.fragmented = (flag & 0x08) == 0x08    // bit 3
	di.hasExtOptions = (flag & 0x04) == 0x04 // bit 2
}

// readTunnelID reads the tunnel ID field if present in the delivery instructions.
// Returns the updated offset and any error encountered.
func readTunnelID(data []byte, offset int, di *DeliveryInstructions) (int, error) {
	if di.deliveryType != DT_TUNNEL {
		return offset, nil
	}

	if len(data) < offset+4 {
		return offset, oops.Errorf("insufficient data for tunnel ID")
	}

	di.tunnelID = binary.BigEndian.Uint32(data[offset : offset+4])
	return offset + 4, nil
}

// readDestinationHash reads the destination hash field if present in the delivery instructions.
// Returns the updated offset and any error encountered.
func readDestinationHash(data []byte, offset int, di *DeliveryInstructions) (int, error) {
	if di.deliveryType != DT_TUNNEL && di.deliveryType != DT_ROUTER {
		return offset, nil
	}

	if len(data) < offset+32 {
		return offset, oops.Errorf("insufficient data for hash")
	}

	copy(di.hash[:], data[offset:offset+32])
	return offset + 32, nil
}

// readDelayIfPresent reads the optional delay field from the delivery instructions.
// Returns the updated offset and any error encountered.
func readDelayIfPresent(data []byte, offset int, di *DeliveryInstructions) (int, error) {
	if !di.hasDelay {
		return offset, nil
	}

	if len(data) < offset+1 {
		return offset, oops.Errorf("insufficient data for delay")
	}

	di.delay = DelayFactor(data[offset])
	return offset + 1, nil
}

// readMessageIDIfFragmented reads the message ID field if the message is fragmented.
// Returns the updated offset and any error encountered.
func readMessageIDIfFragmented(data []byte, offset int, di *DeliveryInstructions) (int, error) {
	if !di.fragmented {
		return offset, nil
	}

	if len(data) < offset+4 {
		return offset, oops.Errorf("insufficient data for message ID")
	}

	di.messageID = binary.BigEndian.Uint32(data[offset : offset+4])
	return offset + 4, nil
}

// readExtendedOptions reads extended options from the delivery instructions if present.
// Returns the updated offset and any error encountered.
func readExtendedOptions(data []byte, offset int, di *DeliveryInstructions) (int, error) {
	if !di.hasExtOptions {
		return offset, nil
	}

	if len(data) < offset+1 {
		return offset, oops.Errorf("insufficient data for extended options length")
	}

	extLen := int(data[offset])
	offset++

	if len(data) < offset+extLen {
		return offset, oops.Errorf("insufficient data for extended options")
	}

	di.extendedOpts = make([]byte, extLen)
	copy(di.extendedOpts, data[offset:offset+extLen])
	return offset + extLen, nil
}

// readFragmentSize reads the fragment size field from the delivery instructions.
// Returns the updated offset and any error encountered.
func readFragmentSize(data []byte, offset int, di *DeliveryInstructions) (int, error) {
	if len(data) < offset+2 {
		return offset, oops.Errorf("insufficient data for fragment size")
	}

	di.fragmentSize = binary.BigEndian.Uint16(data[offset : offset+2])
	return offset + 2, nil
}

func (di *DeliveryInstructions) serializeFollowOnFragment() ([]byte, error) {
	result := make([]byte, 7)

	// Build flag byte: 1nnnnnnd
	flag := byte(0x80)                            // Set bit 7
	flag |= byte((di.fragmentNumber & 0x3F) << 1) // Set bits 6-1
	if di.lastFragment {
		flag |= 0x01 // Set bit 0
	}
	result[0] = flag

	// Message ID (4 bytes)
	binary.BigEndian.PutUint32(result[1:5], di.messageID)

	// Fragment size (2 bytes)
	binary.BigEndian.PutUint16(result[5:7], di.fragmentSize)

	return result, nil
}

func (di *DeliveryInstructions) serializeFirstFragment() ([]byte, error) {
	result := make([]byte, 0, 128)

	flag := di.buildFlagByte()
	result = append(result, flag)

	result = di.appendTunnelIDIfPresent(result)
	result = di.appendHashIfPresent(result)
	result = di.appendDelayIfPresent(result)
	result = di.appendMessageIDIfFragmented(result)
	result = di.appendExtendedOptionsIfPresent(result)
	result = di.appendFragmentSize(result)

	return result, nil
}

// buildFlagByte constructs the flag byte for first fragment delivery instructions.
// It encodes delivery type, delay flag, fragmentation flag, and extended options flag.
func (di *DeliveryInstructions) buildFlagByte() byte {
	flag := byte(0x00)                    // Bit 7 = 0 for first fragment
	flag |= (di.deliveryType & 0x03) << 5 // Bits 6-5
	if di.hasDelay {
		flag |= 0x10 // Bit 4
	}
	if di.fragmented {
		flag |= 0x08 // Bit 3
	}
	if di.hasExtOptions {
		flag |= 0x04 // Bit 2
	}
	return flag
}

// appendTunnelIDIfPresent adds the tunnel ID to the result if delivery type is DT_TUNNEL.
func (di *DeliveryInstructions) appendTunnelIDIfPresent(result []byte) []byte {
	if di.deliveryType == DT_TUNNEL {
		tunnelBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(tunnelBytes, di.tunnelID)
		result = append(result, tunnelBytes...)
	}
	return result
}

// appendHashIfPresent adds the destination hash to the result if delivery type requires it.
func (di *DeliveryInstructions) appendHashIfPresent(result []byte) []byte {
	if di.deliveryType == DT_TUNNEL || di.deliveryType == DT_ROUTER {
		result = append(result, di.hash[:]...)
	}
	return result
}

// appendDelayIfPresent adds the delay byte to the result if the delay flag is set.
func (di *DeliveryInstructions) appendDelayIfPresent(result []byte) []byte {
	if di.hasDelay {
		result = append(result, byte(di.delay))
	}
	return result
}

// appendMessageIDIfFragmented adds the message ID to the result if the message is fragmented.
func (di *DeliveryInstructions) appendMessageIDIfFragmented(result []byte) []byte {
	if di.fragmented {
		msgBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(msgBytes, di.messageID)
		result = append(result, msgBytes...)
	}
	return result
}

// appendExtendedOptionsIfPresent adds extended options to the result if the flag is set.
func (di *DeliveryInstructions) appendExtendedOptionsIfPresent(result []byte) []byte {
	if di.hasExtOptions {
		result = append(result, byte(len(di.extendedOpts)))
		result = append(result, di.extendedOpts...)
	}
	return result
}

// appendFragmentSize adds the fragment size field to the result.
func (di *DeliveryInstructions) appendFragmentSize(result []byte) []byte {
	sizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeBytes, di.fragmentSize)
	result = append(result, sizeBytes...)
	return result
}

// Return if the DeliveryInstructions are of type FIRST_FRAGMENT or FOLLOW_ON_FRAGMENT.
func (delivery_instructions *DeliveryInstructions) Type() (int, error) {
	log.Debug("Determining DeliveryInstructions type")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return 0, oops.Errorf("DeliveryInstructions is nil")
	}
	log.WithField("fragment_type", delivery_instructions.fragmentType).Debug("DeliveryInstructions type retrieved")
	return delivery_instructions.fragmentType, nil
}

// Read the integer stored in the 6-1 bits of a FOLLOW_ON_FRAGMENT's flag, indicating
// the fragment number.
func (delivery_instructions *DeliveryInstructions) FragmentNumber() (int, error) {
	log.Debug("Getting FragmentNumber")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return 0, oops.Errorf("DeliveryInstructions is nil")
	}
	if delivery_instructions.fragmentType != FOLLOW_ON_FRAGMENT {
		log.Error("Fragment Number only exists on FOLLOW_ON_FRAGMENT Delivery Instructions")
		return 0, oops.Errorf("Fragment Number only exists on FOLLOW_ON_FRAGMENT Delivery Instructions")
	}
	log.WithField("fragment_number", delivery_instructions.fragmentNumber).Debug("FragmentNumber retrieved")
	return delivery_instructions.fragmentNumber, nil
}

// Read the value of the 0 bit of a FOLLOW_ON_FRAGMENT, which is set to 1 to indicate the
// last fragment.
func (delivery_instructions *DeliveryInstructions) LastFollowOnFragment() (bool, error) {
	log.Debug("Checking if this is the LastFollowOnFragment")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return false, oops.Errorf("DeliveryInstructions is nil")
	}
	if delivery_instructions.fragmentType != FOLLOW_ON_FRAGMENT {
		log.Error("Last Fragment only exists for FOLLOW_ON_FRAGMENT Delivery Instructions")
		return false, oops.Errorf("Last Fragment only exists for FOLLOW_ON_FRAGMENT Delivery Instructions")
	}
	log.WithField("is_last", delivery_instructions.lastFragment).Debug("LastFollowOnFragment status determined")
	return delivery_instructions.lastFragment, nil
}

// Return the delivery type for these DeliveryInstructions, can be of type
// DT_LOCAL, DT_TUNNEL, DT_ROUTER, or DT_UNUSED.
func (delivery_instructions *DeliveryInstructions) DeliveryType() (byte, error) {
	log.Debug("Getting DeliveryType")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return 0, oops.Errorf("DeliveryInstructions is nil")
	}
	if delivery_instructions.fragmentType != FIRST_FRAGMENT {
		log.Error("DeliveryType only exists for FIRST_FRAGMENT Delivery Instructions")
		return 0, oops.Errorf("DeliveryType only exists for FIRST_FRAGMENT Delivery Instructions")
	}
	log.WithField("delivery_type", delivery_instructions.deliveryType).Debug("DeliveryType retrieved")
	return delivery_instructions.deliveryType, nil
}

// Check if the delay bit is set.  This feature in unimplemented in the Java router.
func (delivery_instructions *DeliveryInstructions) HasDelay() (bool, error) {
	log.Debug("Checking if DeliveryInstructions has delay")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return false, oops.Errorf("DeliveryInstructions is nil")
	}
	if delivery_instructions.fragmentType != FIRST_FRAGMENT {
		log.Error("HasDelay only exists for FIRST_FRAGMENT Delivery Instructions")
		return false, oops.Errorf("HasDelay only exists for FIRST_FRAGMENT Delivery Instructions")
	}
	if delivery_instructions.hasDelay {
		log.WithFields(logger.Fields{
			"at":   "(DeliveryInstructions) HasDelay",
			"info": "this feature is unimplemented in the Java router",
		}).Warn("DeliveryInstructions found with delay bit set")
	}
	log.WithField("has_delay", delivery_instructions.hasDelay).Debug("HasDelay status determined")
	return delivery_instructions.hasDelay, nil
}

// Returns true if the Delivery Instructions are fragmented or false
// if the following data contains the entire message
func (delivery_instructions *DeliveryInstructions) Fragmented() (bool, error) {
	log.Debug("Checking if DeliveryInstructions is fragmented")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return false, oops.Errorf("DeliveryInstructions is nil")
	}
	if delivery_instructions.fragmentType != FIRST_FRAGMENT {
		log.Error("Fragmented only exists for FIRST_FRAGMENT Delivery Instructions")
		return false, oops.Errorf("Fragmented only exists for FIRST_FRAGMENT Delivery Instructions")
	}
	log.WithField("fragmented", delivery_instructions.fragmented).Debug("Fragmented status determined")
	return delivery_instructions.fragmented, nil
}

// Check if the extended options bit is set.  This feature in unimplemented in the Java router.
func (delivery_instructions *DeliveryInstructions) HasExtendedOptions() (bool, error) {
	log.Debug("Checking if DeliveryInstructions has extended options")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return false, oops.Errorf("DeliveryInstructions is nil")
	}
	if delivery_instructions.fragmentType != FIRST_FRAGMENT {
		log.Error("HasExtendedOptions only exists for FIRST_FRAGMENT Delivery Instructions")
		return false, oops.Errorf("HasExtendedOptions only exists for FIRST_FRAGMENT Delivery Instructions")
	}
	if delivery_instructions.hasExtOptions {
		log.WithFields(logger.Fields{
			"at":   "(DeliveryInstructions) ExtendedOptions",
			"info": "this feature is unimplemented in the Java router",
		}).Warn("DeliveryInstructions found with extended_options bit set")
	}
	log.WithField("has_extended_options", delivery_instructions.hasExtOptions).Debug("HasExtendedOptions status determined")
	return delivery_instructions.hasExtOptions, nil
}

// Check if the DeliveryInstructions is of type DT_TUNNEL.
func (delivery_instructions *DeliveryInstructions) HasTunnelID() (bool, error) {
	log.Debug("Checking if DeliveryInstructions has TunnelID")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return false, oops.Errorf("DeliveryInstructions is nil")
	}
	if delivery_instructions.fragmentType != FIRST_FRAGMENT {
		log.Error("HasTunnelID only exists for FIRST_FRAGMENT Delivery Instructions")
		return false, oops.Errorf("HasTunnelID only exists for FIRST_FRAGMENT Delivery Instructions")
	}
	hasTunnelID := delivery_instructions.deliveryType == DT_TUNNEL
	log.WithField("has_tunnel_id", hasTunnelID).Debug("HasTunnelID status determined")
	return hasTunnelID, nil
}

func (delivery_instructions *DeliveryInstructions) HasHash() (bool, error) {
	log.Debug("Checking if DeliveryInstructions has Hash")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return false, oops.Errorf("DeliveryInstructions is nil")
	}
	if delivery_instructions.fragmentType != FIRST_FRAGMENT {
		log.Error("HasHash only exists for FIRST_FRAGMENT Delivery Instructions")
		return false, oops.Errorf("HasHash only exists for FIRST_FRAGMENT Delivery Instructions")
	}
	hasHash := delivery_instructions.deliveryType == DT_TUNNEL || delivery_instructions.deliveryType == DT_ROUTER
	log.WithField("has_hash", hasHash).Debug("HasHash status determined")
	return hasHash, nil
}

// Return the tunnel ID in this DeliveryInstructions or 0 and an error if the
// DeliveryInstructions are not of type DT_TUNNEL.
func (delivery_instructions *DeliveryInstructions) TunnelID() (tunnel_id uint32, err error) {
	log.Debug("Getting TunnelID")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return 0, oops.Errorf("DeliveryInstructions is nil")
	}
	if delivery_instructions.fragmentType != FIRST_FRAGMENT {
		log.Error("TunnelID only exists for FIRST_FRAGMENT Delivery Instructions")
		return 0, oops.Errorf("TunnelID only exists for FIRST_FRAGMENT Delivery Instructions")
	}
	if delivery_instructions.deliveryType != DT_TUNNEL {
		log.Error("DeliveryInstructions are not of type DT_TUNNEL")
		return 0, oops.Errorf("DeliveryInstructions are not of type DT_TUNNEL")
	}
	log.WithField("tunnel_id", delivery_instructions.tunnelID).Debug("TunnelID retrieved")
	return delivery_instructions.tunnelID, nil
}

// Return the hash for these DeliveryInstructions, which varies by hash type.
//
//	If the type is DT_TUNNEL, hash is the SHA256 of the gateway router, if
//	the type is DT_ROUTER it is the SHA256 of the router.
func (delivery_instructions *DeliveryInstructions) Hash() (hash common.Hash, err error) {
	log.Debug("Getting Hash")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return common.Hash{}, oops.Errorf("DeliveryInstructions is nil")
	}
	if delivery_instructions.fragmentType != FIRST_FRAGMENT {
		log.Error("Hash only exists for FIRST_FRAGMENT Delivery Instructions")
		return common.Hash{}, oops.Errorf("Hash only exists for FIRST_FRAGMENT Delivery Instructions")
	}
	if delivery_instructions.deliveryType != DT_TUNNEL && delivery_instructions.deliveryType != DT_ROUTER {
		log.Error("No Hash on DeliveryInstructions not of type DT_TUNNEL or DT_ROUTER")
		return common.Hash{}, oops.Errorf("No Hash on DeliveryInstructions not of type DT_TUNNEL or DT_ROUTER")
	}
	log.WithField("hash", delivery_instructions.hash).Debug("Hash retrieved")
	return delivery_instructions.hash, nil
}

func (delivery_instructions *DeliveryInstructions) Delay() (delay_factor DelayFactor, err error) {
	log.Debug("Getting Delay")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return 0, oops.Errorf("DeliveryInstructions is nil")
	}
	if delivery_instructions.fragmentType != FIRST_FRAGMENT {
		log.Error("Delay only exists for FIRST_FRAGMENT Delivery Instructions")
		return 0, oops.Errorf("Delay only exists for FIRST_FRAGMENT Delivery Instructions")
	}
	if !delivery_instructions.hasDelay {
		return 0, nil
	}
	if delivery_instructions.deliveryType != DT_TUNNEL && delivery_instructions.deliveryType != DT_ROUTER {
		log.WithFields(logger.Fields{
			"at": "(DeliveryInstructions) Delay",
		}).Warn("Delay not present on DeliveryInstructions not of type DT_TUNNEL or DT_ROUTER")
	}
	log.WithField("delay_factor", delivery_instructions.delay).Debug("Delay factor retrieved")
	return delivery_instructions.delay, nil
}

// Return the I2NP Message ID or 0 and an error if the data is not available for this
// DeliveryInstructions.
func (delivery_instructions *DeliveryInstructions) MessageID() (msgid uint32, err error) {
	log.Debug("Getting MessageID")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return 0, oops.Errorf("DeliveryInstructions is nil")
	}
	// MessageID is present for both FIRST_FRAGMENT (if fragmented) and FOLLOW_ON_FRAGMENT
	if delivery_instructions.fragmentType == FIRST_FRAGMENT && !delivery_instructions.fragmented {
		log.Error("No Message ID for non-fragmented FIRST_FRAGMENT Delivery Instructions")
		return 0, oops.Errorf("No Message ID for non-fragmented FIRST_FRAGMENT Delivery Instructions")
	}
	log.WithField("message_id", delivery_instructions.messageID).Debug("MessageID retrieved")
	return delivery_instructions.messageID, nil
}

// Return the Extended Options data if present, or an error if not present.  Extended Options in unimplemented
// in the Java router and the presence of extended options will generate a warning.
func (delivery_instructions *DeliveryInstructions) ExtendedOptions() (data []byte, err error) {
	log.Debug("Getting ExtendedOptions")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return nil, oops.Errorf("DeliveryInstructions is nil")
	}
	if delivery_instructions.fragmentType != FIRST_FRAGMENT {
		log.Error("ExtendedOptions only exists for FIRST_FRAGMENT Delivery Instructions")
		return nil, oops.Errorf("ExtendedOptions only exists for FIRST_FRAGMENT Delivery Instructions")
	}
	if !delivery_instructions.hasExtOptions {
		log.Error("DeliveryInstruction does not have the ExtendedOptions flag set")
		return nil, oops.Errorf("DeliveryInstruction does not have the ExtendedOptions flag set")
	}
	log.WithField("extended_options_length", len(delivery_instructions.extendedOpts)).Debug("Extended Options retrieved")
	return delivery_instructions.extendedOpts, nil
}

// Return the size of the associated I2NP fragment and an error if the data is unavailable.
func (delivery_instructions *DeliveryInstructions) FragmentSize() (frag_size uint16, err error) {
	log.Debug("Getting FragmentSize")
	if delivery_instructions == nil {
		log.Error("DeliveryInstructions is nil")
		return 0, oops.Errorf("DeliveryInstructions is nil")
	}
	log.WithField("fragment_size", delivery_instructions.fragmentSize).Debug("FragmentSize retrieved")
	return delivery_instructions.fragmentSize, nil
}

// Legacy helper functions have been removed - no longer needed with struct-based implementation

func readDeliveryInstructions(data []byte) (instructions *DeliveryInstructions, remainder []byte, err error) {
	log.Debug("Reading DeliveryInstructions")
	return readDeliveryInstructionsStruct(data)
}

// NewLocalDeliveryInstructions creates delivery instructions for LOCAL delivery.
// LOCAL delivery means the message should be processed locally by the current router.
// This is used for both inbound tunnels (standard) and outbound tunnels (when message
// arrives at the final hop).
//
// Parameters:
//   - fragmentSize: The size of the message fragment to deliver
//
// Returns:
//   - *DeliveryInstructions: A new delivery instruction configured for LOCAL delivery
//
// The resulting instruction will have:
//   - deliveryType: DT_LOCAL
//   - fragmentType: FIRST_FRAGMENT
//   - fragmented: false (unfragmented message)
//   - hasDelay: false
//   - hasExtOptions: false
func NewLocalDeliveryInstructions(fragmentSize uint16) *DeliveryInstructions {
	return &DeliveryInstructions{
		fragmentType:  FIRST_FRAGMENT,
		deliveryType:  DT_LOCAL,
		hasDelay:      false,
		fragmented:    false,
		hasExtOptions: false,
		fragmentSize:  fragmentSize,
	}
}

// NewTunnelDeliveryInstructions creates delivery instructions for TUNNEL delivery.
// TUNNEL delivery routes the message to a specific tunnel on a gateway router.
//
// Parameters:
//   - tunnelID: The destination tunnel ID
//   - gatewayHash: SHA-256 hash of the gateway router's identity
//   - fragmentSize: The size of the message fragment
//
// Returns:
//   - *DeliveryInstructions: A new delivery instruction configured for TUNNEL delivery
func NewTunnelDeliveryInstructions(tunnelID uint32, gatewayHash [32]byte, fragmentSize uint16) *DeliveryInstructions {
	return &DeliveryInstructions{
		fragmentType:  FIRST_FRAGMENT,
		deliveryType:  DT_TUNNEL,
		tunnelID:      tunnelID,
		hash:          gatewayHash,
		hasDelay:      false,
		fragmented:    false,
		hasExtOptions: false,
		fragmentSize:  fragmentSize,
	}
}

// NewRouterDeliveryInstructions creates delivery instructions for ROUTER delivery.
// ROUTER delivery sends the message directly to a specific router (not through a tunnel).
//
// Parameters:
//   - routerHash: SHA-256 hash of the destination router's identity
//   - fragmentSize: The size of the message fragment
//
// Returns:
//   - *DeliveryInstructions: A new delivery instruction configured for ROUTER delivery
func NewRouterDeliveryInstructions(routerHash [32]byte, fragmentSize uint16) *DeliveryInstructions {
	return &DeliveryInstructions{
		fragmentType:  FIRST_FRAGMENT,
		deliveryType:  DT_ROUTER,
		hash:          routerHash,
		hasDelay:      false,
		fragmented:    false,
		hasExtOptions: false,
		fragmentSize:  fragmentSize,
	}
}

// readDeliveryInstructionsStruct parses raw bytes into a DeliveryInstructions struct
func readDeliveryInstructionsStruct(data []byte) (instructions *DeliveryInstructions, remainder []byte, err error) {
	if len(data) < 1 {
		log.Error("No data provided")
		return nil, nil, oops.Errorf("no data provided")
	}

	flag := data[0]

	// Determine fragment type from bit 7
	if (flag & 0x80) == 0x80 {
		return readFollowOnFragmentInstructions(data, flag)
	}

	return readFirstFragmentInstructions(data, flag)
}

// readFollowOnFragmentInstructions parses follow-on fragment delivery instructions from the provided data.
// It extracts the fragment details and returns the parsed instructions with remaining data.
func readFollowOnFragmentInstructions(data []byte, flag byte) (*DeliveryInstructions, []byte, error) {
	di, offset, err := parseFollowOnFragment(data, flag)
	if err != nil {
		return nil, nil, err
	}
	remainder := data[offset:]
	log.WithFields(logger.Fields{
		"instructions_offset": offset,
		"remainder_length":    len(remainder),
	}).Debug("Successfully read DeliveryInstructions")
	return di, remainder, nil
}

// readFirstFragmentInstructions parses first fragment delivery instructions from the provided data.
// It processes all required and optional fields in sequence and returns the parsed instructions.
func readFirstFragmentInstructions(data []byte, flag byte) (*DeliveryInstructions, []byte, error) {
	di := &DeliveryInstructions{}
	parseFirstFragmentFlags(di, flag)

	// Reject reserved/unused delivery type 0x03 (DT_UNUSED)
	if di.deliveryType == DT_UNUSED {
		return nil, nil, oops.Errorf("invalid delivery type 0x03 (reserved/unused)")
	}

	offset, err := parseFirstFragmentFields(data, di)
	if err != nil {
		return nil, nil, err
	}

	remainder := data[offset:]
	log.WithFields(logger.Fields{
		"instructions_offset": offset,
		"remainder_length":    len(remainder),
	}).Debug("Successfully read DeliveryInstructions")

	return di, remainder, nil
}

// parseFirstFragmentFields reads all variable-length fields from first fragment delivery instructions.
// It processes tunnel ID, hash, delay, message ID, extended options, and fragment size in sequence.
func parseFirstFragmentFields(data []byte, di *DeliveryInstructions) (int, error) {
	return executeFieldParsers(data, di, []fieldParser{
		readTunnelID,
		readDestinationHash,
		readDelayIfPresent,
		readMessageIDIfFragmented,
		readExtendedOptions,
		readFragmentSize,
	})
}

// fieldParser defines a function that reads a field from delivery instructions.
type fieldParser func([]byte, int, *DeliveryInstructions) (int, error)

// executeFieldParsers sequentially executes field parsers starting from offset 1.
// Returns the final offset after all parsers complete or an error if any parser fails.
func executeFieldParsers(data []byte, di *DeliveryInstructions, parsers []fieldParser) (int, error) {
	offset := 1
	for _, parser := range parsers {
		newOffset, err := parser(data, offset, di)
		if err != nil {
			return offset, err
		}
		offset = newOffset
	}
	return offset, nil
}
