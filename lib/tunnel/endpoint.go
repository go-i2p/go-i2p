package tunnel

import (
	"crypto/sha256"
	"errors"

	"github.com/go-i2p/crypto/tunnel"
)

// MessageHandler is a callback function for processing received I2NP messages.
// It receives the unwrapped message bytes and returns an error if processing fails.
type MessageHandler func(msgBytes []byte) error

// Endpoint handles receiving encrypted tunnel messages,
// decrypting them, and extracting I2NP messages.
//
// Design decisions:
// - Simple callback-based message delivery
// - Works with raw bytes to avoid import cycles
// - Uses crypto/tunnel package with ECIES-X25519-AEAD (ChaCha20/Poly1305) by default
// - Supports both modern ECIES and legacy AES-256-CBC for compatibility
// - Handles fragment reassembly for large messages
// - Clear error handling and logging
type Endpoint struct {
	tunnelID   TunnelID
	decryption tunnel.TunnelEncryptor
	handler    MessageHandler
	// fragments maps message ID to accumulated fragments
	fragments map[uint32]*fragmentAssembler
}

// fragmentAssembler tracks fragments for a single message being reassembled.
// It accumulates message fragments identified by a common message ID and
// reassembles them into a complete I2NP message when all parts are received.
//
// Design rationale:
// - Uses a map indexed by fragment number for O(1) lookup
// - Tracks received fragments with a bitmap for efficient checking
// - Stores delivery type from first fragment for proper routing
// - Supports up to 63 follow-on fragments (6-bit fragment number in spec)
type fragmentAssembler struct {
	fragments    map[int][]byte // fragment number -> fragment data
	deliveryType byte           // Delivery type from first fragment
	totalCount   int            // Expected number of fragments (0 until last fragment seen)
	receivedMask uint64         // Bitmap of received fragments (supports up to 64 fragments)
}

var (
	// ErrNilDecryption is returned when decryption is nil
	ErrNilDecryption = errors.New("decryption tunnel cannot be nil")
	// ErrNilHandler is returned when message handler is nil
	ErrNilHandler = errors.New("message handler cannot be nil")
	// ErrInvalidTunnelData is returned when tunnel data is malformed
	ErrInvalidTunnelData = errors.New("invalid tunnel data")
	// ErrChecksumMismatch is returned when checksum validation fails
	ErrChecksumMismatch = errors.New("tunnel message checksum mismatch")
	// ErrTooManyFragments is returned when fragment number exceeds maximum
	ErrTooManyFragments = errors.New("fragment number exceeds maximum (63)")
	// ErrDuplicateFragment is returned when a fragment is received twice
	ErrDuplicateFragment = errors.New("duplicate fragment received")
)

// NewEndpoint creates a new tunnel endpoint.
//
// Parameters:
// - tunnelID: the ID of this tunnel
// - decryption: the tunnel decryption object for layered decryption
// - handler: callback function to process received I2NP messages
//
// Returns an error if decryption or handler is nil.
func NewEndpoint(tunnelID TunnelID, decryption tunnel.TunnelEncryptor, handler MessageHandler) (*Endpoint, error) {
	if decryption == nil {
		return nil, ErrNilDecryption
	}
	if handler == nil {
		return nil, ErrNilHandler
	}

	ep := &Endpoint{
		tunnelID:   tunnelID,
		decryption: decryption,
		handler:    handler,
		fragments:  make(map[uint32]*fragmentAssembler),
	}

	log.WithField("tunnel_id", tunnelID).Debug("Created tunnel endpoint")
	return ep, nil
}

// Receive processes an encrypted tunnel message.
//
// Process:
// 1. Decrypt the tunnel message
// 2. Validate checksum
// 3. Parse delivery instructions
// 4. Extract message fragments
// 5. Reassemble if fragmented
// 6. Deliver to handler
//
// Returns an error if processing fails at any step.
func (e *Endpoint) Receive(encryptedData []byte) error {
	if len(encryptedData) != 1028 {
		log.WithField("size", len(encryptedData)).Error("Invalid tunnel data size")
		return ErrInvalidTunnelData
	}

	// Decrypt the tunnel message
	decrypted, err := e.decryptTunnelMessage(encryptedData)
	if err != nil {
		return err
	}

	// Validate checksum
	if err := e.validateChecksum(decrypted); err != nil {
		return err
	}

	// Parse and process delivery instructions
	if err := e.processDeliveryInstructions(decrypted); err != nil {
		return err
	}

	log.WithField("tunnel_id", e.tunnelID).Debug("Successfully received message through endpoint")
	return nil
}

// decryptTunnelMessage applies tunnel decryption to the encrypted data.
// Supports both modern ECIES-X25519 and legacy AES-256-CBC decryption.
func (e *Endpoint) decryptTunnelMessage(encryptedData []byte) ([]byte, error) {
	// The TunnelEncryptor interface now returns errors for better error handling
	// Modern ECIES-X25519 uses ChaCha20/Poly1305 AEAD for authenticated decryption
	// Legacy AES uses AES-256-CBC with dual-layer decryption
	decrypted, err := e.decryption.Decrypt(encryptedData)
	if err != nil {
		log.WithError(err).Error("Failed to decrypt tunnel message")
		return nil, err
	}

	return decrypted, nil
}

// validateChecksum verifies the tunnel message checksum.
func (e *Endpoint) validateChecksum(decrypted []byte) error {
	// Extract IV (bytes 4-20) and checksum (bytes 20-24)
	iv := decrypted[4:20]
	expectedChecksum := decrypted[20:24]

	// Calculate checksum: first 4 bytes of SHA256(data after checksum + IV)
	dataAfterChecksum := decrypted[24:]
	checksumData := append(dataAfterChecksum, iv...)
	hash := sha256.Sum256(checksumData)
	actualChecksum := hash[:4]

	// Compare checksums
	for i := 0; i < 4; i++ {
		if expectedChecksum[i] != actualChecksum[i] {
			log.WithFields(map[string]interface{}{
				"expected": expectedChecksum,
				"actual":   actualChecksum,
			}).Error("Checksum mismatch")
			return ErrChecksumMismatch
		}
	}

	return nil
}

// processDeliveryInstructions parses delivery instructions and extracts messages.
func (e *Endpoint) processDeliveryInstructions(decrypted []byte) error {
	dataStart, err := e.findDataStart(decrypted)
	if err != nil {
		return err
	}

	return e.processInstructionLoop(decrypted[dataStart:])
}

// findDataStart locates the zero byte separator in tunnel message.
// It searches for the zero byte that separates padding from delivery instructions.
// Returns the position immediately after the zero byte, or an error if not found.
func (e *Endpoint) findDataStart(decrypted []byte) (int, error) {
	for i := 24; i < len(decrypted); i++ {
		if decrypted[i] == 0x00 {
			return i + 1, nil
		}
	}
	log.Error("No zero byte separator found in tunnel message")
	return -1, ErrInvalidTunnelData
}

// processInstructionLoop iterates through all delivery instructions in the data.
// It processes each instruction, handling both complete and fragmented messages.
// Returns an error if message processing fails.
func (e *Endpoint) processInstructionLoop(data []byte) error {
	for len(data) >= 3 {
		di, remainder, err := readDeliveryInstructions(data)
		if err != nil {
			log.WithError(err).Error("Failed to read delivery instructions")
			return err
		}

		fragSize, fragmentData, remainder, err := e.extractFragmentData(di, remainder)
		if err != nil {
			return err
		}
		if fragmentData == nil {
			break // Insufficient data
		}

		if err := e.processFragmentByType(di, fragmentData); err != nil {
			return err
		}

		data = remainder[fragSize:]
	}
	return nil
}

// extractFragmentData extracts fragment data from the remainder based on delivery instructions.
// Returns fragment size, fragment data, remainder, and error.
// Returns nil fragmentData if there's insufficient data (not an error condition).
func (e *Endpoint) extractFragmentData(di *DeliveryInstructions, remainder []byte) (uint16, []byte, []byte, error) {
	fragSize, err := di.FragmentSize()
	if err != nil {
		log.WithError(err).Error("Failed to get fragment size")
		return 0, nil, nil, err
	}

	if len(remainder) < int(fragSize) {
		log.WithFields(map[string]interface{}{
			"expected": fragSize,
			"actual":   len(remainder),
		}).Warn("Insufficient data for fragment")
		return fragSize, nil, remainder, nil
	}

	return fragSize, remainder[:fragSize], remainder, nil
}

// processFragmentByType processes a fragment based on its type (first or follow-on).
func (e *Endpoint) processFragmentByType(di *DeliveryInstructions, fragmentData []byte) error {
	fragmentType, err := di.Type()
	if err != nil {
		log.WithError(err).Error("Failed to determine fragment type")
		return err
	}

	if fragmentType == FIRST_FRAGMENT {
		return e.processFirstFragment(di, fragmentData)
	} else if fragmentType == FOLLOW_ON_FRAGMENT {
		return e.processFollowOnFragment(di, fragmentData)
	}
	return nil
}

// processFirstFragment handles the first fragment of a message.
// If not fragmented, delivers immediately. If fragmented, starts reassembly.
func (e *Endpoint) processFirstFragment(di *DeliveryInstructions, fragmentData []byte) error {
	fragmented, err := di.Fragmented()
	if err != nil {
		return err
	}

	deliveryType, err := di.DeliveryType()
	if err != nil {
		return err
	}

	// If not fragmented, deliver immediately
	if !fragmented {
		if deliveryType == DT_LOCAL {
			return e.handler(fragmentData)
		}
		log.WithField("delivery_type", deliveryType).Debug("Non-local delivery, skipping")
		return nil
	}

	// Handle fragmented message - store first fragment
	msgID, err := di.MessageID()
	if err != nil {
		return err
	}

	// Get or create assembler for this message
	assembler, exists := e.fragments[msgID]
	if !exists {
		// Create new assembler for this message
		assembler = &fragmentAssembler{
			fragments:    make(map[int][]byte),
			deliveryType: deliveryType,
			totalCount:   0, // Will be set when last fragment arrives
			receivedMask: 0,
		}
		e.fragments[msgID] = assembler
	} else {
		// Update delivery type if assembler already exists from follow-on fragments
		assembler.deliveryType = deliveryType
	}

	// Store fragment 0
	assembler.fragments[0] = fragmentData
	assembler.receivedMask |= 1 // Set bit 0

	log.WithFields(map[string]interface{}{
		"message_id": msgID,
		"size":       len(fragmentData),
	}).Debug("Stored first fragment")

	// Check if we have all fragments (in case follow-on fragments arrived first)
	if assembler.totalCount > 0 {
		expectedMask := (uint64(1) << assembler.totalCount) - 1
		if assembler.receivedMask == expectedMask {
			return e.reassembleAndDeliver(msgID, assembler)
		}
	}

	return nil
}

// processFollowOnFragment handles subsequent fragments of a fragmented message.
// Reassembles and delivers when all fragments are received.
func (e *Endpoint) processFollowOnFragment(di *DeliveryInstructions, fragmentData []byte) error {
	msgID, err := di.MessageID()
	if err != nil {
		return err
	}

	fragmentNum, err := di.FragmentNumber()
	if err != nil {
		return err
	}

	isLast, err := di.LastFollowOnFragment()
	if err != nil {
		return err
	}

	// Validate fragment number (0-63 range, but 0 is for first fragment)
	if fragmentNum < 1 || fragmentNum > 63 {
		log.WithField("fragment_num", fragmentNum).Error("Invalid fragment number")
		return ErrTooManyFragments
	}

	// Get or create assembler
	assembler, exists := e.fragments[msgID]
	if !exists {
		log.WithField("message_id", msgID).Warn("Received follow-on fragment without first fragment")
		// Create assembler anyway - might get first fragment later
		assembler = &fragmentAssembler{
			fragments:    make(map[int][]byte),
			deliveryType: DT_LOCAL, // Default to local
			totalCount:   0,
			receivedMask: 0,
		}
		e.fragments[msgID] = assembler
	}

	// Check for duplicate
	mask := uint64(1) << fragmentNum
	if (assembler.receivedMask & mask) != 0 {
		log.WithFields(map[string]interface{}{
			"message_id":   msgID,
			"fragment_num": fragmentNum,
		}).Warn("Duplicate fragment received")
		return ErrDuplicateFragment
	}

	// Store fragment
	assembler.fragments[fragmentNum] = fragmentData
	assembler.receivedMask |= mask

	// If this is the last fragment, record total count
	if isLast {
		assembler.totalCount = fragmentNum + 1
		log.WithFields(map[string]interface{}{
			"message_id":   msgID,
			"total_count":  assembler.totalCount,
			"fragment_num": fragmentNum,
		}).Debug("Received last fragment")
	}

	// Check if we have all fragments
	if assembler.totalCount > 0 {
		expectedMask := (uint64(1) << assembler.totalCount) - 1
		if assembler.receivedMask == expectedMask {
			return e.reassembleAndDeliver(msgID, assembler)
		}
	}

	log.WithFields(map[string]interface{}{
		"message_id":   msgID,
		"fragment_num": fragmentNum,
		"is_last":      isLast,
	}).Debug("Stored follow-on fragment, waiting for more")

	return nil
}

// reassembleAndDeliver combines all fragments and delivers the complete message.
func (e *Endpoint) reassembleAndDeliver(msgID uint32, assembler *fragmentAssembler) error {
	// Calculate total size
	totalSize := 0
	for i := 0; i < assembler.totalCount; i++ {
		frag, exists := assembler.fragments[i]
		if !exists {
			log.WithFields(map[string]interface{}{
				"message_id":   msgID,
				"fragment_num": i,
			}).Error("Missing fragment during reassembly")
			return errors.New("missing fragment")
		}
		totalSize += len(frag)
	}

	// Reassemble
	completeMsg := make([]byte, 0, totalSize)
	for i := 0; i < assembler.totalCount; i++ {
		completeMsg = append(completeMsg, assembler.fragments[i]...)
	}

	log.WithFields(map[string]interface{}{
		"message_id":   msgID,
		"total_size":   totalSize,
		"fragment_cnt": assembler.totalCount,
	}).Debug("Reassembled fragmented message")

	// Clean up
	delete(e.fragments, msgID)

	// Deliver if local
	if assembler.deliveryType == DT_LOCAL {
		return e.handler(completeMsg)
	}

	log.WithField("delivery_type", assembler.deliveryType).Debug("Non-local delivery, skipping")
	return nil
}

// TunnelID returns the ID of this endpoint's tunnel
func (e *Endpoint) TunnelID() TunnelID {
	return e.tunnelID
}

// ClearFragments clears all accumulated fragments (useful for cleanup)
func (e *Endpoint) ClearFragments() {
	e.fragments = make(map[uint32]*fragmentAssembler)
	log.WithField("tunnel_id", e.tunnelID).Debug("Cleared fragment cache")
}
