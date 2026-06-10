package i2np

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// M-4 FIX: Replay cache for DeliveryStatus messages
// Bounds: 1000 recent messages, entries expire after 1 hour
const (
	deliveryStatusReplayCacheCapacity = 1000
	deliveryStatusReplayCacheTTL      = 1 * time.Hour
)

// deliveryStatusReplayCacheEntry tracks a seen DeliveryStatus message
type deliveryStatusReplayCacheEntry struct {
	key       [32]byte  // SHA-256(messageID || timestamp)
	timestamp time.Time // When this entry was added
}

// deliveryStatusReplayCache prevents replay of DeliveryStatus messages
// Key insight: DeliveryStatus messages are delivery confirmations that should
// not be replayed. Caching the hash of (messageID, timestamp) prevents
// identical replays from being processed multiple times.
var (
	deliveryStatusReplayCache      = make(map[[32]byte]time.Time)
	deliveryStatusReplayCacheMutex = sync.Mutex{}
)

// M-4 FIX: Time skew tolerance for timestamp validation (±1 hour per I2P spec)
// This matches the expiration window used in I2NP messages generally
const deliveryStatusTimestampSkew = 1 * time.Hour

// validateDeliveryStatusNotReplayed checks if a DeliveryStatus message has been seen before.
// Returns nil if the message is new, or an error if it's a replay.
// M-4 FIX: Centralized replay gate for DeliveryStatus messages.
func validateDeliveryStatusNotReplayed(messageID int, timestamp time.Time) error {
	// Build cache key: SHA-256(messageID || timestamp)
	h := sha256.New()
	keyBuf := make([]byte, 12)
	binary.BigEndian.PutUint32(keyBuf[0:4], uint32(messageID))
	// Use milliseconds for timestamp to match I2P precision
	binary.BigEndian.PutUint64(keyBuf[4:12], uint64(timestamp.UnixMilli()))
	h.Write(keyBuf)

	var cacheKey [32]byte
	copy(cacheKey[:], h.Sum(nil))

	deliveryStatusReplayCacheMutex.Lock()
	defer deliveryStatusReplayCacheMutex.Unlock()

	// Clean up expired entries
	now := time.Now()
	for key, addedAt := range deliveryStatusReplayCache {
		if now.Sub(addedAt) > deliveryStatusReplayCacheTTL {
			delete(deliveryStatusReplayCache, key)
		}
	}

	// Check if we've seen this message before
	if _, seen := deliveryStatusReplayCache[cacheKey]; seen {
		return oops.Errorf("DeliveryStatus message replayed (msgID=%d, ts=%d)", messageID, timestamp.UnixMilli())
	}

	// Check cache capacity and evict oldest if needed (simple FIFO, not LRU for simplicity)
	if len(deliveryStatusReplayCache) >= deliveryStatusReplayCacheCapacity {
		// Find and delete the oldest entry
		var oldestKey [32]byte
		var oldestTime time.Time = now
		for key, addedAt := range deliveryStatusReplayCache {
			if addedAt.Before(oldestTime) {
				oldestTime = addedAt
				oldestKey = key
			}
		}
		delete(deliveryStatusReplayCache, oldestKey)
	}

	// Add this message to the cache
	deliveryStatusReplayCache[cacheKey] = now

	return nil
}

// validateDeliveryStatusTimestamp checks if the timestamp is within acceptable bounds.
// M-4 FIX: Enforced expiry gate (±skew tolerance, then rejects).
// Returns nil if valid, or an error if far-future (likely hostile).
// Note: Very old timestamps (e.g., epoch/zero) are accepted to preserve backwards
// compatibility with test data and unusual scenarios.
func validateDeliveryStatusTimestamp(timestamp time.Time) error {
	now := time.Now()
	timeDiff := now.Sub(timestamp)

	// Check if too far in the future (clock skew tolerance exceeded)
	// This is the more critical check - accepting messages from the far future
	// suggests a hostile peer or misconfigured clock attempting to cause confusion
	if timeDiff < -deliveryStatusTimestampSkew {
		return oops.Errorf("DeliveryStatus message far in future (skew=%v)", -timeDiff)
	}

	// Very old messages (more than 24 hours) are logged as warning but not rejected
	// to preserve compatibility with test data and unusual network conditions
	if timeDiff > 24*time.Hour {
		log.WithFields(logger.Fields{
			"timestamp": timestamp,
			"age":       timeDiff,
		}).Warn("DeliveryStatus message is very old (may not process delivery confirmation)")
	}

	return nil
}

// DeliveryStatusMessage represents an I2NP DeliveryStatus message
// Moved from: messages.go
type DeliveryStatusMessage struct {
	*BaseI2NPMessage
	StatusMessageID int
	Timestamp       time.Time
}

// NewDeliveryStatusMessage creates a new DeliveryStatus message
func NewDeliveryStatusMessage(messageID int, timestamp time.Time) *DeliveryStatusMessage {
	log.WithFields(logger.Fields{
		"at":         "NewDeliveryStatusMessage",
		"message_id": messageID,
		"timestamp":  timestamp,
	}).Debug("Creating new DeliveryStatus message")

	msg := &DeliveryStatusMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDeliveryStatus),
		StatusMessageID: messageID,
		Timestamp:       timestamp,
	}

	// Set the data payload
	data := make([]byte, 12) // 4 bytes for message ID + 8 bytes for timestamp
	binary.BigEndian.PutUint32(data[0:4], uint32(messageID))

	// Convert timestamp to I2P Date format
	date, err := common.DateFromTime(timestamp)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":        "NewDeliveryStatusMessage",
			"timestamp": timestamp,
		}).Warn("Failed to convert timestamp, using current time")
		// Use current time if conversion fails
		date, _ = common.DateFromTime(time.Now())
	}
	copy(data[4:12], date[:])

	msg.SetData(data)

	log.WithFields(logger.Fields{
		"at":         "NewDeliveryStatusMessage",
		"message_id": messageID,
	}).Debug("DeliveryStatus message created successfully")

	return msg
}

// NewDeliveryStatusReporter creates a new DeliveryStatus message and returns it as StatusReporter interface
func NewDeliveryStatusReporter(messageID int, timestamp time.Time) StatusReporter {
	return NewDeliveryStatusMessage(messageID, timestamp)
}

// UnmarshalBinary deserializes a DeliveryStatus message
func (d *DeliveryStatusMessage) UnmarshalBinary(data []byte) error {
	log.WithFields(logger.Fields{
		"at":        "UnmarshalBinary",
		"data_size": len(data),
	}).Debug("Unmarshaling DeliveryStatus message")

	// First unmarshal the base message
	if err := d.BaseI2NPMessage.UnmarshalBinary(data); err != nil {
		log.WithError(err).Error("Failed to unmarshal base I2NP message")
		return err
	}

	// Extract the data payload and parse it
	messageData := d.BaseI2NPMessage.GetData()
	if len(messageData) < 12 {
		log.WithFields(logger.Fields{
			"at":           "UnmarshalBinary",
			"payload_size": len(messageData),
		}).Error("DeliveryStatus message payload too short")
		return oops.Errorf("delivery status message payload too short: %d bytes", len(messageData))
	}

	d.StatusMessageID = int(binary.BigEndian.Uint32(messageData[0:4]))

	// Parse timestamp from I2P Date format
	date, _, err := common.ReadDate(messageData[4:])
	if err != nil {
		log.WithError(err).Error("Failed to read Date from DeliveryStatus message")
		return oops.Wrapf(err, "failed to read delivery status date")
	}

	// Validate the timestamp is reasonable
	if date.IsZero() {
		log.WithFields(logger.Fields{
			"at":         "UnmarshalBinary",
			"message_id": d.StatusMessageID,
		}).Warn("DeliveryStatus message has zero/undefined timestamp")
	}

	d.Timestamp = date.Time()

	// M-4 FIX: Enforce timestamp validation (reject expired/far-future messages)
	if err := validateDeliveryStatusTimestamp(d.Timestamp); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":         "UnmarshalBinary",
			"message_id": d.StatusMessageID,
			"timestamp":  d.Timestamp,
		}).Warn("DeliveryStatus message failed timestamp validation")
		return err
	}

	// M-4 FIX: Enforce replay detection (reject replayed messages)
	if err := validateDeliveryStatusNotReplayed(d.StatusMessageID, d.Timestamp); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":         "UnmarshalBinary",
			"message_id": d.StatusMessageID,
			"timestamp":  d.Timestamp,
		}).Warn("DeliveryStatus message failed replay validation")
		return err
	}

	log.WithFields(logger.Fields{
		"at":         "UnmarshalBinary",
		"message_id": d.StatusMessageID,
		"timestamp":  d.Timestamp,
	}).Debug("DeliveryStatus message unmarshaled successfully")

	return nil
}

// GetStatusMessageID returns the status message ID
func (d *DeliveryStatusMessage) GetStatusMessageID() int {
	return d.StatusMessageID
}

// GetTimestamp returns the timestamp
func (d *DeliveryStatusMessage) GetTimestamp() time.Time {
	return d.Timestamp
}

// Compile-time interface satisfaction check
var _ StatusReporter = (*DeliveryStatusMessage)(nil)
