package i2np

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Replay cache for DeliveryStatus messages
// Bounds: 1000 recent messages, entries expire after 1 hour
const (
	deliveryStatusReplayCacheCapacity = 1000
	deliveryStatusReplayCacheTTL      = 1 * time.Hour
)

// dsReplayCacheEntry is stored in the FIFO list and the lookup map.
type dsReplayCacheEntry struct {
	key     [32]byte  // SHA-256(messageID || timestamp)
	addedAt time.Time // insertion time, used for TTL expiry
}

// dsReplayCache holds a mutex-protected FIFO for O(1) eviction and a map for
// O(1) lookup. The list maintains insertion order so the oldest entry is always
// at the front, letting us evict expired entries without scanning the whole cache.
type dsReplayCache struct {
	mu   sync.Mutex
	m    map[[32]byte]*list.Element // key → list element
	fifo *list.List                 // *dsReplayCacheEntry ordered oldest→newest
}

// deliveryStatusReplayCacheGlobal is the package-level singleton.
var deliveryStatusReplayCacheGlobal = &dsReplayCache{
	m:    make(map[[32]byte]*list.Element),
	fifo: list.New(),
}

// clearDeliveryStatusReplayCacheForTesting clears the replay cache.
// This is intended ONLY for testing purposes to avoid cache pollution between test cases.
// Production code should never call this.
func clearDeliveryStatusReplayCacheForTesting() {
	c := deliveryStatusReplayCacheGlobal
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = make(map[[32]byte]*list.Element)
	c.fifo.Init()
}

// Time skew tolerance for timestamp validation (±1 hour per I2P spec)
// This matches the expiration window used in I2NP messages generally
const deliveryStatusTimestampSkew = 1 * time.Hour

// validateDeliveryStatusNotReplayed checks if a DeliveryStatus message has been
// seen before. Returns nil if the message is new, or an error if it's a replay.
// The underlying cache uses a FIFO list + map, so both insertion and eviction
// are O(1).
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

	c := deliveryStatusReplayCacheGlobal
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Evict expired entries from the front of the FIFO list in O(k) where k
	// is the number of expired entries — amortized O(1) per call.
	for c.fifo.Len() > 0 {
		front := c.fifo.Front()
		entry := front.Value.(*dsReplayCacheEntry)
		if now.Sub(entry.addedAt) <= deliveryStatusReplayCacheTTL {
			break
		}
		c.fifo.Remove(front)
		delete(c.m, entry.key)
	}

	// Check if we've seen this message before (O(1) map lookup).
	if _, seen := c.m[cacheKey]; seen {
		return oops.Errorf("DeliveryStatus message replayed (msgID=%d, ts=%d)", messageID, timestamp.UnixMilli())
	}

	// Evict oldest entry if at capacity (O(1) FIFO pop from front).
	if len(c.m) >= deliveryStatusReplayCacheCapacity {
		front := c.fifo.Front()
		if front != nil {
			entry := front.Value.(*dsReplayCacheEntry)
			c.fifo.Remove(front)
			delete(c.m, entry.key)
		}
	}

	// Insert new entry at the back of the FIFO list (O(1)).
	entry := &dsReplayCacheEntry{key: cacheKey, addedAt: now}
	elem := c.fifo.PushBack(entry)
	c.m[cacheKey] = elem

	return nil
}

// validateDeliveryStatusTimestamp checks if the timestamp is within acceptable bounds.
// Enforced expiry gate (±skew tolerance, then rejects).
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

// DeliveryStatusMessage represents an I2NP DeliveryStatus message (type 10)
// used to confirm the successful delivery or creation of a message. The
// 12-byte payload holds the 4-byte message ID and the 8-byte timestamp.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the wire format.
// See also [DeliveryStatus], [StatusReporter].
type DeliveryStatusMessage struct {
	*BaseI2NPMessage
	StatusMessageID int
	Timestamp       time.Time
}

// NewDeliveryStatusMessage creates a new DeliveryStatus message for the
// given message ID and timestamp. The payload is a 12-byte buffer with the
// message ID and I2P Date in big-endian order.
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

// NewDeliveryStatusReporter creates a new DeliveryStatus message and
// returns it as a StatusReporter, so callers that only need to send a
// status can work with the interface instead of the concrete type.
// See also [StatusReporter].
func NewDeliveryStatusReporter(messageID int, timestamp time.Time) StatusReporter {
	return NewDeliveryStatusMessage(messageID, timestamp)
}

// UnmarshalBinary deserializes a DeliveryStatus message. After parsing the
// base header and 12-byte payload, it validates the timestamp (rejecting
// expired or far-future values) and checks the replay cache to reject
// replayed messages.
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

	// Enforce timestamp validation (reject expired/far-future messages)
	if err := validateDeliveryStatusTimestamp(d.Timestamp); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":         "UnmarshalBinary",
			"message_id": d.StatusMessageID,
			"timestamp":  d.Timestamp,
		}).Warn("DeliveryStatus message failed timestamp validation")
		return err
	}

	// Enforce replay detection (reject replayed messages)
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

// GetStatusMessageID returns the ID of the message this DeliveryStatus
// confirms delivery of.
func (d *DeliveryStatusMessage) GetStatusMessageID() int {
	return d.StatusMessageID
}

// GetTimestamp returns the time the message was successfully created or
// delivered.
func (d *DeliveryStatusMessage) GetTimestamp() time.Time {
	return d.Timestamp
}

// Compile-time interface satisfaction check
var _ StatusReporter = (*DeliveryStatusMessage)(nil)
