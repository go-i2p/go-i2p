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
	// DTLocal indicates delivery to the local router context.
	DTLocal = iota
	DTTunnel
	DTRouter
	DTUnused
)

const (
	// FirstFragment marks the first fragment in a message sequence.
	FirstFragment = iota
	FollowOnFragment
)

const (
	// FlagSize is the size in bytes of a fragment flag field.
	FlagSize               = 1
	TunnelIDSize           = 4
	HashSize               = 32
	DelaySize              = 1
	MessageIDSize          = 4
	ExtendedOptionsMinSize = 2
	SizeFieldSize          = 2
)

// DelayFactor represents a delay factor byte for tunnel message delivery instructions.
type DelayFactor byte

// DeliveryInstructions represents I2P tunnel message delivery instructions
type DeliveryInstructions struct {
	// Type: FirstFragment or FollowOnFragment
	fragmentType int

	// For FirstFragment
	deliveryType  byte // DTLocal, DTTunnel, DTRouter
	hasDelay      bool
	fragmented    bool
	hasExtOptions bool
	tunnelID      uint32      // Present if deliveryType == DTTunnel
	hash          common.Hash // Present if deliveryType == DTTunnel or DTRouter
	delay         DelayFactor // Present if hasDelay
	messageID     uint32      // Present if fragmented
	extendedOpts  []byte      // Present if hasExtOptions
	fragmentSize  uint16

	// For FollowOnFragment
	fragmentNumber int
	lastFragment   bool
	// messageID and fragmentSize also used for FollowOnFragment
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

	if di.fragmentType == FollowOnFragment {
		return di.serializeFollowOnFragment()
	}
	return di.serializeFirstFragment()
}

// guardNil checks if the receiver is nil and logs an error.
func (di *DeliveryInstructions) guardNil(at string) error {
	if di == nil {
		logAt(at).Error("DeliveryInstructions is nil")
		return oops.Errorf("DeliveryInstructions is nil")
	}
	return nil
}

// guardFragmentType checks if the fragment type matches the expected type and logs an error if not.
func (di *DeliveryInstructions) guardFragmentType(expectedType int, at, msg string) error {
	if di.fragmentType != expectedType {
		logAt(at).Error(msg)
		return oops.Errorf("%s", msg)
	}
	return nil
}

// parseFollowOnFragment reads a follow-on fragment delivery instruction from the provided data.
// It extracts the fragment number, last fragment flag, message ID, and fragment size.
// Returns the parsed DeliveryInstructions and the number of bytes consumed.
func parseFollowOnFragment(data []byte, flag byte) (*DeliveryInstructions, int, error) {
	di := &DeliveryInstructions{}
	di.fragmentType = FollowOnFragment
	di.fragmentNumber = int((flag & 0x7e) >> 1)
	di.lastFragment = (flag & 0x01) == 0x01

	if len(data) < 7 {
		return nil, 0, oops.Errorf("insufficient data for FollowOnFragment")
	}

	di.messageID = binary.BigEndian.Uint32(data[1:5])
	di.fragmentSize = binary.BigEndian.Uint16(data[5:7])
	return di, 7, nil
}

// parseFirstFragmentFlags extracts delivery type and feature flags from the first fragment flag byte.
func parseFirstFragmentFlags(di *DeliveryInstructions, flag byte) {
	di.fragmentType = FirstFragment
	di.deliveryType = (flag & 0x60) >> 5     // bits 6-5
	di.hasDelay = (flag & 0x10) == 0x10      // bit 4
	di.fragmented = (flag & 0x08) == 0x08    // bit 3
	di.hasExtOptions = (flag & 0x04) == 0x04 // bit 2
}

// need checks if the buffer has enough space starting at offset for n bytes.
// If not, returns an error describing the required field.
// This is a helper to avoid repeating bounds checks across the delivery parsing functions.
func need(data []byte, offset, n int, what string) error {
	if len(data) < offset+n {
		return oops.Errorf("insufficient data for %s", what)
	}
	return nil
}

// readTunnelID reads the tunnel ID field if present in the delivery instructions.
// Returns the updated offset and any error encountered.
func readTunnelID(data []byte, offset int, di *DeliveryInstructions) (int, error) {
	if di.deliveryType != DTTunnel {
		return offset, nil
	}

	if err := need(data, offset, 4, "tunnel ID"); err != nil {
		return offset, err
	}

	di.tunnelID = binary.BigEndian.Uint32(data[offset : offset+4])
	return offset + 4, nil
}

// readDestinationHash reads the destination hash field if present in the delivery instructions.
// Returns the updated offset and any error encountered.
func readDestinationHash(data []byte, offset int, di *DeliveryInstructions) (int, error) {
	if di.deliveryType != DTTunnel && di.deliveryType != DTRouter {
		return offset, nil
	}

	hash, _, err := common.ReadHash(data[offset:])
	if err != nil {
		return offset, oops.Errorf("insufficient data for hash")
	}
	di.hash = hash
	return offset + 32, nil
}

// readDelayIfPresent reads the optional delay field from the delivery instructions.
// Returns the updated offset and any error encountered.
func readDelayIfPresent(data []byte, offset int, di *DeliveryInstructions) (int, error) {
	if !di.hasDelay {
		return offset, nil
	}

	if err := need(data, offset, 1, "delay"); err != nil {
		return offset, err
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

	if err := need(data, offset, 4, "message ID"); err != nil {
		return offset, err
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

	if err := need(data, offset, 1, "extended options length"); err != nil {
		return offset, err
	}

	extLen := int(data[offset])
	offset++

	if err := need(data, offset, extLen, "extended options"); err != nil {
		return offset, err
	}

	di.extendedOpts = make([]byte, extLen)
	copy(di.extendedOpts, data[offset:offset+extLen])
	return offset + extLen, nil
}

// readFragmentSize reads the fragment size field from the delivery instructions.
// Returns the updated offset and any error encountered.
func readFragmentSize(data []byte, offset int, di *DeliveryInstructions) (int, error) {
	if err := need(data, offset, 2, "fragment size"); err != nil {
		return offset, err
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

// appendTunnelIDIfPresent adds the tunnel ID to the result if delivery type is DTTunnel.
func (di *DeliveryInstructions) appendTunnelIDIfPresent(result []byte) []byte {
	if di.deliveryType == DTTunnel {
		// Use stack-allocated array to avoid heap allocation
		var tunnelBytes [4]byte
		binary.BigEndian.PutUint32(tunnelBytes[:], di.tunnelID)
		result = append(result, tunnelBytes[:]...)
	}
	return result
}

// appendHashIfPresent adds the destination hash to the result if delivery type requires it.
func (di *DeliveryInstructions) appendHashIfPresent(result []byte) []byte {
	if di.deliveryType == DTTunnel || di.deliveryType == DTRouter {
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
		// Use stack-allocated array to avoid heap allocation
		var msgBytes [4]byte
		binary.BigEndian.PutUint32(msgBytes[:], di.messageID)
		result = append(result, msgBytes[:]...)
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
	// Use stack-allocated array to avoid heap allocation
	var sizeBytes [2]byte
	binary.BigEndian.PutUint16(sizeBytes[:], di.fragmentSize)
	result = append(result, sizeBytes[:]...)
	return result
}

// Type returns if the DeliveryInstructions are of type FirstFragment or FollowOnFragment.
func (di *DeliveryInstructions) Type() (int, error) {
	logAt("Type").Debug("Determining DeliveryInstructions type")
	if err := di.guardNil("Type"); err != nil {
		return 0, err
	}
	log.WithField("fragment_type", di.fragmentType).Debug("DeliveryInstructions type retrieved")
	return di.fragmentType, nil
}

// FragmentNumber reads the integer stored in the 6-1 bits of a FollowOnFragment's flag, indicating
// the fragment number.
func (di *DeliveryInstructions) FragmentNumber() (int, error) {
	logAt("FragmentNumber").Debug("Getting FragmentNumber")
	if err := di.guardNil("FragmentNumber"); err != nil {
		return 0, err
	}
	if err := di.guardFragmentType(FollowOnFragment, "FragmentNumber", "Fragment Number only exists on FollowOnFragment Delivery Instructions"); err != nil {
		return 0, err
	}
	log.WithField("fragment_number", di.fragmentNumber).Debug("FragmentNumber retrieved")
	return di.fragmentNumber, nil
}

// LastFollowOnFragment reads the value of the 0 bit of a FollowOnFragment, which is set to 1 to indicate the
// last fragment.
func (di *DeliveryInstructions) LastFollowOnFragment() (bool, error) {
	logAt("LastFollowOnFragment").Debug("Checking if this is the LastFollowOnFragment")
	if err := di.guardNil("LastFollowOnFragment"); err != nil {
		return false, err
	}
	if err := di.guardFragmentType(FollowOnFragment, "LastFollowOnFragment", "Last Fragment only exists for FollowOnFragment Delivery Instructions"); err != nil {
		return false, err
	}
	log.WithField("is_last", di.lastFragment).Debug("LastFollowOnFragment status determined")
	return di.lastFragment, nil
}

// DeliveryType returns the delivery type for these DeliveryInstructions, can be of type
// DTLocal, DTTunnel, DTRouter, or DTUnused.
func (di *DeliveryInstructions) DeliveryType() (byte, error) {
	logAt("DeliveryType").Debug("Getting DeliveryType")
	if err := di.guardNil("DeliveryType"); err != nil {
		return 0, err
	}
	if err := di.guardFragmentType(FirstFragment, "DeliveryType", "DeliveryType only exists for FirstFragment Delivery Instructions"); err != nil {
		return 0, err
	}
	log.WithField("delivery_type", di.deliveryType).Debug("DeliveryType retrieved")
	return di.deliveryType, nil
}

// HasDelay checks if the delay bit is set. This feature is unimplemented in the Java router.
func (di *DeliveryInstructions) HasDelay() (bool, error) {
	logAt("HasDelay").Debug("Checking if DeliveryInstructions has delay")
	if err := di.guardNil("HasDelay"); err != nil {
		return false, err
	}
	if err := di.guardFragmentType(FirstFragment, "HasDelay", "HasDelay only exists for FirstFragment Delivery Instructions"); err != nil {
		return false, err
	}
	if di.hasDelay {
		logAt("(DeliveryInstructions) HasDelay").WithFields(logger.Fields{"info": "this feature is unimplemented in the Java router"}).Warn("DeliveryInstructions found with delay bit set")
	}
	log.WithField("has_delay", di.hasDelay).Debug("HasDelay status determined")
	return di.hasDelay, nil
}

// Fragmented returns true if the Delivery Instructions are fragmented or false
// if the following data contains the entire message
func (di *DeliveryInstructions) Fragmented() (bool, error) {
	logAt("Fragmented").Debug("Checking if DeliveryInstructions is fragmented")
	if err := di.guardNil("Fragmented"); err != nil {
		return false, err
	}
	if err := di.guardFragmentType(FirstFragment, "Fragmented", "Fragmented only exists for FirstFragment Delivery Instructions"); err != nil {
		return false, err
	}
	log.WithField("fragmented", di.fragmented).Debug("Fragmented status determined")
	return di.fragmented, nil
}

// HasExtendedOptions checks if the extended options bit is set. This feature is unimplemented in the Java router.
func (di *DeliveryInstructions) HasExtendedOptions() (bool, error) {
	logAt("HasExtendedOptions").Debug("Checking if DeliveryInstructions has extended options")
	if err := di.guardNil("HasExtendedOptions"); err != nil {
		return false, err
	}
	if err := di.guardFragmentType(FirstFragment, "HasExtendedOptions", "HasExtendedOptions only exists for FirstFragment Delivery Instructions"); err != nil {
		return false, err
	}
	if di.hasExtOptions {
		logAt("(DeliveryInstructions) ExtendedOptions").WithFields(logger.Fields{"info": "this feature is unimplemented in the Java router"}).Warn("DeliveryInstructions found with extended_options bit set")
	}
	log.WithField("has_extended_options", di.hasExtOptions).Debug("HasExtendedOptions status determined")
	return di.hasExtOptions, nil
}

// HasTunnelID checks if the DeliveryInstructions is of type DTTunnel.
func (di *DeliveryInstructions) HasTunnelID() (bool, error) {
	logAt("HasTunnelID").Debug("Checking if DeliveryInstructions has TunnelID")
	if err := di.guardNil("HasTunnelID"); err != nil {
		return false, err
	}
	if err := di.guardFragmentType(FirstFragment, "HasTunnelID", "HasTunnelID only exists for FirstFragment Delivery Instructions"); err != nil {
		return false, err
	}
	hasTunnelID := di.deliveryType == DTTunnel
	log.WithField("has_tunnel_id", hasTunnelID).Debug("HasTunnelID status determined")
	return hasTunnelID, nil
}

// HasHash returns true if the DeliveryInstructions contain a hash field, which is present for DTTunnel and DTRouter delivery types.
func (di *DeliveryInstructions) HasHash() (bool, error) {
	logAt("HasHash").Debug("Checking if DeliveryInstructions has Hash")
	if err := di.guardNil("HasHash"); err != nil {
		return false, err
	}
	if err := di.guardFragmentType(FirstFragment, "HasHash", "HasHash only exists for FirstFragment Delivery Instructions"); err != nil {
		return false, err
	}
	hasHash := di.deliveryType == DTTunnel || di.deliveryType == DTRouter
	log.WithField("has_hash", hasHash).Debug("HasHash status determined")
	return hasHash, nil
}

// TunnelID returns the tunnel ID in this DeliveryInstructions or 0 and an error if the
// DeliveryInstructions are not of type DTTunnel.
func (di *DeliveryInstructions) TunnelID() (tunnelID uint32, err error) {
	logAt("TunnelID").Debug("Getting TunnelID")
	if err := di.guardNil("TunnelID"); err != nil {
		return 0, err
	}
	if err := di.guardFragmentType(FirstFragment, "TunnelID", "TunnelID only exists for FirstFragment Delivery Instructions"); err != nil {
		return 0, err
	}
	if di.deliveryType != DTTunnel {
		logAt("TunnelID").Error("DeliveryInstructions are not of type DTTunnel")
		return 0, oops.Errorf("DeliveryInstructions are not of type DTTunnel")
	}
	log.WithField("tunnelID", di.tunnelID).Debug("TunnelID retrieved")
	return di.tunnelID, nil
}

// Hash returns the hash for these DeliveryInstructions, which varies by hash type.
//
//	If the type is DTTunnel, hash is the SHA256 of the gateway router, if
//	the type is DTRouter it is the SHA256 of the router.
func (di *DeliveryInstructions) Hash() (hash common.Hash, err error) {
	logAt("Hash").Debug("Getting Hash")
	if err := di.guardNil("Hash"); err != nil {
		return common.Hash{}, err
	}
	if err := di.guardFragmentType(FirstFragment, "Hash", "Hash only exists for FirstFragment Delivery Instructions"); err != nil {
		return common.Hash{}, err
	}
	if di.deliveryType != DTTunnel && di.deliveryType != DTRouter {
		logAt("Hash").Error("No Hash on DeliveryInstructions not of type DTTunnel or DTRouter")
		return common.Hash{}, oops.Errorf("No Hash on DeliveryInstructions not of type DTTunnel or DTRouter")
	}
	log.WithField("hash", di.hash).Debug("Hash retrieved")
	return di.hash, nil
}

// Delay returns the delay factor for these DeliveryInstructions, or an error if the instructions are not a FirstFragment or have no delay set.
func (di *DeliveryInstructions) Delay() (delayFactor DelayFactor, err error) {
	logAt("Delay").Debug("Getting Delay")
	if err := di.guardNil("Delay"); err != nil {
		return 0, err
	}
	if err := di.guardFragmentType(FirstFragment, "Delay", "Delay only exists for FirstFragment Delivery Instructions"); err != nil {
		return 0, err
	}
	if !di.hasDelay {
		return 0, nil
	}
	if di.deliveryType != DTTunnel && di.deliveryType != DTRouter {
		logAt("(DeliveryInstructions) Delay").WithFields(logger.Fields{}).Warn("Delay not present on DeliveryInstructions not of type DTTunnel or DTRouter")
	}
	log.WithField("delayFactor", di.delay).Debug("Delay factor retrieved")
	return di.delay, nil
}

// MessageID returns the I2NP Message ID or 0 and an error if the data is not available for this
// DeliveryInstructions.
func (di *DeliveryInstructions) MessageID() (msgid uint32, err error) {
	logAt("MessageID").Debug("Getting MessageID")
	if err := di.guardNil("MessageID"); err != nil {
		return 0, err
	}
	// MessageID is present for both FirstFragment (if fragmented) and FollowOnFragment
	if di.fragmentType == FirstFragment && !di.fragmented {
		logAt("MessageID").Error("No Message ID for non-fragmented FirstFragment Delivery Instructions")
		return 0, oops.Errorf("No Message ID for non-fragmented FirstFragment Delivery Instructions")
	}
	log.WithField("message_id", di.messageID).Debug("MessageID retrieved")
	return di.messageID, nil
}

// ExtendedOptions returns the Extended Options data if present, or an error if not present. Extended Options is unimplemented
// in the Java router and the presence of extended options will generate a warning.
func (di *DeliveryInstructions) ExtendedOptions() (data []byte, err error) {
	logAt("ExtendedOptions").Debug("Getting ExtendedOptions")
	if err := di.guardNil("ExtendedOptions"); err != nil {
		return nil, err
	}
	if err := di.guardFragmentType(FirstFragment, "ExtendedOptions", "ExtendedOptions only exists for FirstFragment Delivery Instructions"); err != nil {
		return nil, err
	}
	if !di.hasExtOptions {
		logAt("ExtendedOptions").Error("DeliveryInstruction does not have the ExtendedOptions flag set")
		return nil, oops.Errorf("DeliveryInstruction does not have the ExtendedOptions flag set")
	}
	log.WithField("extended_options_length", len(di.extendedOpts)).Debug("Extended Options retrieved")
	return di.extendedOpts, nil
}

// FragmentSize returns the size of the associated I2NP fragment and an error if the data is unavailable.
func (di *DeliveryInstructions) FragmentSize() (fragSize uint16, err error) {
	logAt("FragmentSize").Debug("Getting FragmentSize")
	if err := di.guardNil("FragmentSize"); err != nil {
		return 0, err
	}
	log.WithField("fragment_size", di.fragmentSize).Debug("FragmentSize retrieved")
	return di.fragmentSize, nil
}

// Legacy helper functions have been removed - no longer needed with struct-based implementation

func readDeliveryInstructions(data []byte) (instructions *DeliveryInstructions, remainder []byte, err error) {
	logAt("readDeliveryInstructions").Debug("Reading DeliveryInstructions")
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
//   - deliveryType: DTLocal
//   - fragmentType: FirstFragment
//   - fragmented: false (unfragmented message)
//   - hasDelay: false
//   - hasExtOptions: false
func NewLocalDeliveryInstructions(fragmentSize uint16) *DeliveryInstructions {
	return &DeliveryInstructions{
		fragmentType:  FirstFragment,
		deliveryType:  DTLocal,
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
		fragmentType:  FirstFragment,
		deliveryType:  DTTunnel,
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
		fragmentType:  FirstFragment,
		deliveryType:  DTRouter,
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
		logAt("readDeliveryInstructionsStruct").Error("No data provided")
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

	// Reject reserved/unused delivery type 0x03 (DTUnused)
	if di.deliveryType == DTUnused {
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
