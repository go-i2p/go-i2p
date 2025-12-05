package tunnel

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"

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
// - Automatic cleanup of stale fragments (default: 60 seconds)
// - Thread-safe for concurrent message processing
// - Clear error handling and logging
type Endpoint struct {
	tunnelID        TunnelID
	decryption      tunnel.TunnelEncryptor
	handler         MessageHandler
	fragmentsMutex  sync.Mutex
	fragments       map[uint32]*fragmentAssembler
	fragmentTimeout time.Duration
	stopChan        chan struct{}
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
// - Tracks creation time for expiration-based cleanup
type fragmentAssembler struct {
	fragments    map[int][]byte // fragment number -> fragment data
	deliveryType byte           // Delivery type from first fragment
	totalCount   int            // Expected number of fragments (0 until last fragment seen)
	receivedMask uint64         // Bitmap of received fragments (supports up to 64 fragments)
	createdAt    time.Time      // Timestamp when first fragment was received
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
	ErrTooManyFragments = errors.New("too many fragments: maximum 63")
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
// Starts a background goroutine to clean up stale fragments.
func NewEndpoint(tunnelID TunnelID, decryption tunnel.TunnelEncryptor, handler MessageHandler) (*Endpoint, error) {
	if decryption == nil {
		return nil, ErrNilDecryption
	}
	if handler == nil {
		return nil, ErrNilHandler
	}

	ep := &Endpoint{
		tunnelID:        tunnelID,
		decryption:      decryption,
		handler:         handler,
		fragments:       make(map[uint32]*fragmentAssembler),
		fragmentTimeout: 60 * time.Second, // Default 60 second timeout for incomplete fragments
		stopChan:        make(chan struct{}),
	}

	// Start background cleanup goroutine
	go ep.cleanupFragments()

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
// Thread-safe: protects fragment map access with mutex.
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

	// Handle non-fragmented messages
	if !fragmented {
		return e.deliverNonFragmentedMessage(deliveryType, fragmentData)
	}

	// Handle fragmented messages
	msgID, err := di.MessageID()
	if err != nil {
		return err
	}

	return e.storeFirstFragment(msgID, deliveryType, fragmentData)
}

// deliverNonFragmentedMessage delivers a complete non-fragmented message immediately.
// Returns nil for non-local delivery types as they are not processed at this endpoint.
func (e *Endpoint) deliverNonFragmentedMessage(deliveryType byte, fragmentData []byte) error {
	if deliveryType == DT_LOCAL {
		return e.handler(fragmentData)
	}
	log.WithField("delivery_type", deliveryType).Debug("Non-local delivery, skipping")
	return nil
}

// storeFirstFragment stores the first fragment of a multi-fragment message.
// Creates or updates the fragment assembler and checks for completion.
func (e *Endpoint) storeFirstFragment(msgID uint32, deliveryType byte, fragmentData []byte) error {
	e.fragmentsMutex.Lock()
	defer e.fragmentsMutex.Unlock()

	assembler := e.ensureAssemblerExists(msgID, deliveryType)
	e.recordFirstFragmentData(assembler, fragmentData, msgID)
	return e.checkFragmentCompletion(msgID, assembler)
}

// ensureAssemblerExists retrieves existing assembler or creates a new one for the message ID.
// Updates delivery type on existing assemblers to ensure correct routing.
// Note: Caller must hold fragmentsMutex.
func (e *Endpoint) ensureAssemblerExists(msgID uint32, deliveryType byte) *fragmentAssembler {
	assembler, exists := e.fragments[msgID]
	if !exists {
		assembler = &fragmentAssembler{
			fragments:    make(map[int][]byte),
			deliveryType: deliveryType,
			totalCount:   0,
			receivedMask: 0,
			createdAt:    time.Now(),
		}
		e.fragments[msgID] = assembler
	} else {
		assembler.deliveryType = deliveryType
	}
	return assembler
}

// recordFirstFragmentData stores the first fragment (index 0) in the assembler.
// Sets the corresponding bit in the received mask for tracking.
func (e *Endpoint) recordFirstFragmentData(assembler *fragmentAssembler, fragmentData []byte, msgID uint32) {
	assembler.fragments[0] = fragmentData
	assembler.receivedMask |= 1

	log.WithFields(map[string]interface{}{
		"message_id": msgID,
		"size":       len(fragmentData),
	}).Debug("Stored first fragment")
}

// checkFragmentCompletion determines if all fragments have been received.
// Triggers reassembly and delivery if the message is complete.
func (e *Endpoint) checkFragmentCompletion(msgID uint32, assembler *fragmentAssembler) error {
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
	msgID, fragmentNum, isLast, err := e.extractFollowOnFragmentInfo(di)
	if err != nil {
		return err
	}

	e.fragmentsMutex.Lock()
	defer e.fragmentsMutex.Unlock()

	assembler := e.getOrCreateAssembler(msgID)

	if err := e.storeFragmentData(msgID, fragmentNum, fragmentData, assembler); err != nil {
		return err
	}

	if isLast {
		e.markLastFragment(msgID, fragmentNum, assembler)
	}

	return e.attemptReassembly(msgID, fragmentNum, isLast, assembler)
}

// extractFollowOnFragmentInfo extracts message ID, fragment number, and last-fragment flag from delivery instructions.
func (e *Endpoint) extractFollowOnFragmentInfo(di *DeliveryInstructions) (uint32, int, bool, error) {
	msgID, err := di.MessageID()
	if err != nil {
		return 0, 0, false, err
	}

	fragmentNum, err := di.FragmentNumber()
	if err != nil {
		return 0, 0, false, err
	}

	// Validate fragment number (0-63 range, but 0 is for first fragment)
	if fragmentNum < 1 || fragmentNum > 63 {
		log.WithField("fragment_num", fragmentNum).Error("Invalid fragment number")
		return 0, 0, false, ErrTooManyFragments
	}

	isLast, err := di.LastFollowOnFragment()
	if err != nil {
		return 0, 0, false, err
	}

	return msgID, fragmentNum, isLast, nil
}

// getOrCreateAssembler retrieves existing assembler or creates a new one for the message ID.
// Note: Caller must hold fragmentsMutex.
func (e *Endpoint) getOrCreateAssembler(msgID uint32) *fragmentAssembler {
	assembler, exists := e.fragments[msgID]
	if !exists {
		log.WithField("message_id", msgID).Warn("Received follow-on fragment without first fragment")
		assembler = &fragmentAssembler{
			fragments:    make(map[int][]byte),
			deliveryType: DT_LOCAL,
			totalCount:   0,
			receivedMask: 0,
			createdAt:    time.Now(),
		}
		e.fragments[msgID] = assembler
	}
	return assembler
}

// storeFragmentData validates and stores fragment data in the assembler.
func (e *Endpoint) storeFragmentData(msgID uint32, fragmentNum int, fragmentData []byte, assembler *fragmentAssembler) error {
	mask := uint64(1) << fragmentNum
	if (assembler.receivedMask & mask) != 0 {
		log.WithFields(map[string]interface{}{
			"message_id":   msgID,
			"fragment_num": fragmentNum,
		}).Warn("Duplicate fragment received")
		return ErrDuplicateFragment
	}

	assembler.fragments[fragmentNum] = fragmentData
	assembler.receivedMask |= mask
	return nil
}

// markLastFragment records that this is the final fragment in the sequence.
func (e *Endpoint) markLastFragment(msgID uint32, fragmentNum int, assembler *fragmentAssembler) {
	assembler.totalCount = fragmentNum + 1
	log.WithFields(map[string]interface{}{
		"message_id":   msgID,
		"total_count":  assembler.totalCount,
		"fragment_num": fragmentNum,
	}).Debug("Received last fragment")
}

// attemptReassembly checks if all fragments are received and triggers reassembly if complete.
func (e *Endpoint) attemptReassembly(msgID uint32, fragmentNum int, isLast bool, assembler *fragmentAssembler) error {
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
	e.fragmentsMutex.Lock()
	defer e.fragmentsMutex.Unlock()

	e.fragments = make(map[uint32]*fragmentAssembler)
	log.WithField("tunnel_id", e.tunnelID).Debug("Cleared fragment cache")
}

// Stop gracefully shuts down the endpoint and stops the cleanup goroutine.
// Should be called when the endpoint is no longer needed to prevent resource leaks.
func (e *Endpoint) Stop() {
	close(e.stopChan)
	log.WithField("tunnel_id", e.tunnelID).Debug("Stopped tunnel endpoint")
}

// cleanupFragments periodically removes stale incomplete fragments.
// Runs in a background goroutine started by NewEndpoint.
// Fragments older than fragmentTimeout are removed to prevent memory leaks.
func (e *Endpoint) cleanupFragments() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.removeStaleFragments()
		case <-e.stopChan:
			return
		}
	}
}

// removeStaleFragments removes fragments that have exceeded the timeout period.
// This prevents memory leaks from incomplete fragmented messages due to packet loss.
func (e *Endpoint) removeStaleFragments() {
	e.fragmentsMutex.Lock()
	defer e.fragmentsMutex.Unlock()

	now := time.Now()
	removedCount := 0

	for msgID, assembler := range e.fragments {
		if now.Sub(assembler.createdAt) > e.fragmentTimeout {
			delete(e.fragments, msgID)
			removedCount++
			log.WithFields(map[string]interface{}{
				"message_id": msgID,
				"age":        now.Sub(assembler.createdAt),
				"fragments":  len(assembler.fragments),
			}).Debug("Removed stale fragment assembler")
		}
	}

	if removedCount > 0 {
		log.WithFields(map[string]interface{}{
			"tunnel_id": e.tunnelID,
			"removed":   removedCount,
			"remaining": len(e.fragments),
		}).Info("Cleaned up stale fragments")
	}
}
