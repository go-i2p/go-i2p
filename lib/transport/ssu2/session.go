package ssu2

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/go-i2p/logger"
)

// retransmitTickInterval is how often the send worker checks for expired
// pending messages that need to be retransmitted.
const retransmitTickInterval = 50 * time.Millisecond

// ccPollInterval is the delay between congestion-window polling attempts
// when the window is full.
const ccPollInterval = 10 * time.Millisecond

// maxRetransmitBackoff caps the exponential back-off delay for retransmissions.
const maxRetransmitBackoff = 60 * time.Second

// maxRTTSample discards implausibly large RTT measurements from one-sided
// clock observations (e.g. when lastSendNano is stale).
const maxRTTSample = 30 * time.Second

// pendingI2NP tracks an I2NP message that has been written to the conn but
// has not yet been confirmed delivered (used for session-level retransmission).
type pendingI2NP struct {
	data     []byte
	blocks   []*ssu2noise.SSU2Block
	sentAt   time.Time
	deadline time.Time // sentAt + rto; extended on each retransmit with back-off
	attempts int
}

// SSU2Session implements transport.TransportSession over an SSU2 connection.
type SSU2Session struct {
	conn *ssu2noise.SSU2Conn

	sendQueue     chan i2np.I2NPMessage
	recvChan      chan i2np.I2NPMessage
	sendQueueSize int32

	bytesSent       uint64
	bytesReceived   uint64
	droppedMessages uint64

	// Phase 5: Reliability & congestion control
	rttEstimator   *ssu2noise.RTTEstimator
	congestionCtrl *ssu2noise.CongestionController
	pendingMsgsMu  sync.Mutex
	pendingMsgs    map[uint64]*pendingI2NP
	pendingSeqNext uint64 // incremented atomically
	maxRetransmit  int
	lastSendNano   int64 // atomic unix-nano of most recent Write call

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	wg        sync.WaitGroup

	callbackMu      sync.Mutex
	cleanupCallback func()
	cleanupOnce     sync.Once

	logger *logger.Entry
}

// NewSSU2Session creates a new SSU2 session and starts background workers.
func NewSSU2Session(conn *ssu2noise.SSU2Conn, ctx context.Context, logger *logger.Entry) *SSU2Session {
	session := NewSSU2SessionDeferred(conn, ctx, logger)
	session.StartWorkers()
	return session
}

// NewSSU2SessionDeferred creates a new SSU2 session without starting workers.
// Call StartWorkers() after confirming the session will be used.
func NewSSU2SessionDeferred(conn *ssu2noise.SSU2Conn, ctx context.Context, logger *logger.Entry) *SSU2Session {
	sessionCtx, cancel := context.WithCancel(ctx)

	sessionLogger := logger.WithFields(map[string]interface{}{
		"component":   "ssu2_session",
		"remote_addr": conn.RemoteAddr().String(),
	})
	sessionLogger.Info("Creating new SSU2 session")

	rtt := ssu2noise.NewRTTEstimator()
	s := &SSU2Session{
		conn:           conn,
		sendQueue:      make(chan i2np.I2NPMessage, 256),
		recvChan:       make(chan i2np.I2NPMessage, 256),
		rttEstimator:   rtt,
		congestionCtrl: ssu2noise.NewCongestionController(rtt),
		pendingMsgs:    make(map[uint64]*pendingI2NP),
		maxRetransmit:  DefaultMaxRetransmissions,
		ctx:            sessionCtx,
		cancel:         cancel,
		logger:         sessionLogger,
	}
	s.wireDataHandlerCallbacks()
	return s
}

// wireDataHandlerCallbacks wires protocol-level callbacks from the go-noise
// DataHandler into the SSU2Session. Called once during session construction,
// before StartWorkers(), so callbacks are active from the first data packet.
func (s *SSU2Session) wireDataHandlerCallbacks() {
	s.conn.SetDataHandlerCallbacks(s.buildMergedCallbacks(nil))
}

// buildMergedCallbacks constructs a DataHandlerCallbacks that combines
// session-local handlers (termination, clock validation) with any
// transport-level handlers supplied in extra. extra may be nil.
func (s *SSU2Session) buildMergedCallbacks(extra *BlockCallbackConfig) ssu2noise.DataHandlerCallbacks {
	cbs := ssu2noise.DataHandlerCallbacks{
		OnTermination: func(_ uint64, reason uint8, _ []byte) {
			s.logger.WithField("termination_reason", reason).Warn("SSU2 session terminated by peer")
			s.cancel()
		},
		OnDateTime: func(timestamp uint32) error {
			now := time.Now().Unix()
			delta := int64(timestamp) - now
			if delta < 0 {
				delta = -delta
			}
			if delta > 60 {
				s.logger.WithField("skew_seconds", delta).Warn("SSU2 clock skew out of tolerance, closing session")
				s.cancel()
				return fmt.Errorf("clock skew %ds exceeds 60s tolerance", delta)
			}
			return nil
		},
	}
	if extra != nil {
		mergeBlockCallbacks(&cbs, extra)
	}
	return cbs
}

// SetTransportCallbacks merges transport-level block callbacks (relay,
// peer-test, router-info, etc.) into the session's DataHandler without
// overwriting the session-local termination and clock-validation handlers.
// Safe to call after construction and before or after StartWorkers().
func (s *SSU2Session) SetTransportCallbacks(cfg *BlockCallbackConfig) {
	if cfg == nil {
		return
	}
	s.conn.SetDataHandlerCallbacks(s.buildMergedCallbacks(cfg))
}

// mergeBlockCallbacks copies non-nil callbacks from cfg into cbs,
// leaving any already-set fields (e.g. OnTermination) untouched.
func mergeBlockCallbacks(cbs *ssu2noise.DataHandlerCallbacks, cfg *BlockCallbackConfig) {
	// Use type-safe callback setters to reduce cyclomatic complexity
	setIfNotNil(&cbs.OnRouterInfo, cfg.OnRouterInfo)
	setIfNotNil(&cbs.OnACK, cfg.OnACK)
	setIfNotNil(&cbs.OnDateTime, cfg.OnDateTime)
	setIfNotNil(&cbs.OnPeerTest, cfg.OnPeerTest)
	setIfNotNil(&cbs.OnRelayRequest, cfg.OnRelayRequest)
	setIfNotNil(&cbs.OnRelayResponse, cfg.OnRelayResponse)
	setIfNotNil(&cbs.OnRelayIntro, cfg.OnRelayIntro)
	setIfNotNil(&cbs.OnNewToken, cfg.OnNewToken)
	setIfNotNil(&cbs.OnAddress, cfg.OnAddress)
	setIfNotNil(&cbs.OnOptions, cfg.OnOptions)
	setIfNotNil(&cbs.OnPathChallenge, cfg.OnPathChallenge)
	setIfNotNil(&cbs.OnPathResponse, cfg.OnPathResponse)
}

// setIfNotNil is a type-parameterized helper that sets *dest = src if src != nil.
func setIfNotNil[T any](dest *T, src T) {
	if any(src) != nil {
		*dest = src
	}
}

// StartWorkers launches the background send and receive goroutines.
func (s *SSU2Session) StartWorkers() {
	s.wg.Add(2)
	go s.sendWorker()
	go s.receiveWorker()
	s.logger.Info("SSU2 session workers started")
}

// QueueSendI2NP queues an I2NP message to be sent over the session.
func (s *SSU2Session) QueueSendI2NP(msg i2np.I2NPMessage) error {
	atomic.AddInt32(&s.sendQueueSize, 1)

	select {
	case s.sendQueue <- msg:
		return nil
	case <-s.ctx.Done():
		atomic.AddInt32(&s.sendQueueSize, -1)
		return fmt.Errorf("session closed, message dropped (type=%d)", msg.Type())
	case <-time.After(500 * time.Millisecond):
		atomic.AddInt32(&s.sendQueueSize, -1)
		return fmt.Errorf("send queue full, message dropped (type=%d)", msg.Type())
	}
}

// SendQueueSize returns how many I2NP messages are not completely sent yet.
func (s *SSU2Session) SendQueueSize() int {
	return int(atomic.LoadInt32(&s.sendQueueSize))
}

// ReadNextI2NP blocking reads the next fully received I2NP message.
func (s *SSU2Session) ReadNextI2NP() (i2np.I2NPMessage, error) {
	select {
	case msg := <-s.recvChan:
		return msg, nil
	case <-s.ctx.Done():
		return nil, ErrSessionClosed
	}
}

// sendQueueDrainTimeout is the maximum time to wait for queued messages.
const sendQueueDrainTimeout = 2 * time.Second

// Close closes the session cleanly.
func (s *SSU2Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.logger.Info("Closing SSU2 session")
		s.drainSendQueue()
		s.cancel()
		if s.conn != nil {
			err = s.conn.Close()
		}
		s.wg.Wait()
		s.callCleanupCallback()
		s.logger.Info("SSU2 session closed")
	})
	return err
}

// SetCleanupCallback sets a callback invoked when the session closes.
func (s *SSU2Session) SetCleanupCallback(callback func()) {
	s.callbackMu.Lock()
	s.cleanupCallback = callback
	s.callbackMu.Unlock()
}

func (s *SSU2Session) callCleanupCallback() {
	s.cleanupOnce.Do(func() {
		s.callbackMu.Lock()
		cb := s.cleanupCallback
		s.callbackMu.Unlock()
		if cb != nil {
			cb()
		}
	})
}

// GetBandwidthStats returns total bytes sent and received by this session.
func (s *SSU2Session) GetBandwidthStats() (bytesSent, bytesReceived uint64) {
	return atomic.LoadUint64(&s.bytesSent), atomic.LoadUint64(&s.bytesReceived)
}

// WriteBlocks writes raw SSU2 blocks directly to the underlying connection,
// bypassing the I2NP send queue. Used for protocol-level blocks such as PeerTest
// and Relay that must not be fragmented or queued alongside I2NP traffic.
func (s *SSU2Session) WriteBlocks(blocks []*ssu2noise.SSU2Block) error {
	return s.conn.WriteBlocks(blocks)
}

func (s *SSU2Session) drainSendQueue() {
	if atomic.LoadInt32(&s.sendQueueSize) == 0 {
		return
	}

	deadline := time.NewTimer(sendQueueDrainTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for s.waitForQueueDrain(deadline, ticker) {
	}
}

// waitForQueueDrain waits for a drain tick and returns true to continue waiting,
// false when done (either queue empty or deadline expired).
func (s *SSU2Session) waitForQueueDrain(deadline *time.Timer, ticker *time.Ticker) bool {
	select {
	case <-deadline.C:
		return false
	case <-ticker.C:
		return atomic.LoadInt32(&s.sendQueueSize) > 0
	}
}

func (s *SSU2Session) sendWorker() {
	defer s.wg.Done()
	ticker := time.NewTicker(retransmitTickInterval)
	defer ticker.Stop()

	for {
		if s.processSendWorkerEvents(ticker) {
			return
		}
	}
}

// processSendWorkerEvents handles a single iteration of the send worker loop.
// Returns true if the worker should exit.
func (s *SSU2Session) processSendWorkerEvents(ticker *time.Ticker) bool {
	select {
	case msg := <-s.sendQueue:
		return s.handleQueuedMessage(msg)
	case <-ticker.C:
		return s.checkRetransmissions()
	case <-s.ctx.Done():
		s.discardRemainingMessages()
		return true
	}
}

// handleQueuedMessage processes a message from the send queue.
// Returns true if the worker should exit due to an error.
func (s *SSU2Session) handleQueuedMessage(msg i2np.I2NPMessage) bool {
	atomic.AddInt32(&s.sendQueueSize, -1)
	if err := s.sendWithCongestionControl(msg); err != nil {
		s.logger.WithError(err).Error("Failed to send message")
		s.discardRemainingMessages()
		return true
	}
	return false
}

// checkRetransmissions handles the retransmission tick.
// Returns true if the worker should exit due to max retransmissions.
func (s *SSU2Session) checkRetransmissions() bool {
	if s.handleRetransmissions() {
		s.logger.Warn("Max retransmissions exceeded, closing session")
		s.cancel()
		return true
	}
	return false
}

// sendWithCongestionControl serializes msg as an SSU2 short-header I2NP
// message, fragments it into correctly-formatted SSU2 blocks, waits for
// congestion-window room, then writes the blocks to the conn.
func (s *SSU2Session) sendWithCongestionControl(msg i2np.I2NPMessage) error {
	data, err := marshalI2NPShort(msg)
	if err != nil {
		return err
	}
	blocks, err := fragmentSSU2Short(data, maxSSU2PayloadIPv6)
	if err != nil {
		return err
	}
	if err := s.waitForCongestionWindow(len(data)); err != nil {
		return err
	}
	return s.sendTrackedBlocks(data, blocks)
}

// marshalI2NPShort converts an I2NP message to the 9-byte SSU2 short header
// format: Type(1) + MessageID(4) + ShortExpiration(4) + Body.
func marshalI2NPShort(msg i2np.I2NPMessage) ([]byte, error) {
	var body []byte
	if dc, ok := msg.(i2np.DataCarrier); ok {
		body = dc.GetData()
	} else {
		full, err := msg.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if len(full) < 16 {
			return nil, fmt.Errorf("NTCP data too short: %d bytes", len(full))
		}
		body = full[16:]
	}
	result := make([]byte, i2np.ShortI2NPHeaderSize+len(body))
	result[0] = byte(msg.Type())
	binary.BigEndian.PutUint32(result[1:5], uint32(msg.MessageID()))
	binary.BigEndian.PutUint32(result[5:9], uint32(msg.Expiration().Unix()))
	copy(result[i2np.ShortI2NPHeaderSize:], body)
	return result, nil
}

// fragmentSSU2Short splits SSU2 short-header data into correctly formatted
// FirstFragment (type 4) and FollowOnFragment (type 5) blocks matching
// the format expected by go-noise's DataHandler.
//
// For messages that fit in a single block, returns a type 3 I2NPMessage block.
//
// FirstFragment format: I2NPType(1) + MessageID(4) + ShortExpiry(4) + BodyChunk
// FollowOnFragment format: FragInfo(1) + MessageID(4) + BodyChunk
func fragmentSSU2Short(data []byte, maxPayload int) ([]*ssu2noise.SSU2Block, error) {
	const blockTLVOverhead = 3 // type(1) + length(2)

	if len(data)+blockTLVOverhead <= maxPayload {
		return []*ssu2noise.SSU2Block{
			ssu2noise.NewSSU2Block(ssu2noise.BlockTypeI2NPMessage, data),
		}, nil
	}

	if len(data) < i2np.ShortI2NPHeaderSize {
		return nil, fmt.Errorf("SSU2 short data too short: %d bytes", len(data))
	}

	// Extract header fields from SSU2 short format
	i2npType := data[0]
	messageID := binary.BigEndian.Uint32(data[1:5])
	shortExpiry := binary.BigEndian.Uint32(data[5:9])
	body := data[i2np.ShortI2NPHeaderSize:]

	// FirstFragment: TLV(3) + I2NPType(1) + MessageID(4) + ShortExpiry(4) + BodyChunk
	const firstFragHeaderSize = 9 // type(1) + msgID(4) + shortExpiry(4)
	maxFirstBody := maxPayload - blockTLVOverhead - firstFragHeaderSize
	if maxFirstBody <= 0 {
		return nil, fmt.Errorf("max payload %d too small for first fragment", maxPayload)
	}

	firstBodySize := maxFirstBody
	if firstBodySize > len(body) {
		firstBodySize = len(body)
	}

	firstData := make([]byte, firstFragHeaderSize+firstBodySize)
	firstData[0] = i2npType
	binary.BigEndian.PutUint32(firstData[1:5], messageID)
	binary.BigEndian.PutUint32(firstData[5:9], shortExpiry)
	copy(firstData[9:], body[:firstBodySize])

	blocks := []*ssu2noise.SSU2Block{
		ssu2noise.NewSSU2Block(ssu2noise.BlockTypeFirstFragment, firstData),
	}

	// FollowOnFragments: TLV(3) + FragInfo(1) + MessageID(4) + BodyChunk
	const followOnHeaderSize = 5 // fragInfo(1) + msgID(4)
	maxFollowBody := maxPayload - blockTLVOverhead - followOnHeaderSize
	if maxFollowBody <= 0 {
		return nil, fmt.Errorf("max payload %d too small for follow-on fragment", maxPayload)
	}

	offset := firstBodySize
	fragNum := uint8(1)
	for offset < len(body) {
		end := offset + maxFollowBody
		if end > len(body) {
			end = len(body)
		}
		isLast := end == len(body)
		fragInfo := fragNum << 1
		if isLast {
			fragInfo |= 0x01
		}

		followData := make([]byte, followOnHeaderSize+(end-offset))
		followData[0] = fragInfo
		binary.BigEndian.PutUint32(followData[1:5], messageID)
		copy(followData[5:], body[offset:end])

		blocks = append(blocks, ssu2noise.NewSSU2Block(ssu2noise.BlockTypeFollowOnFragment, followData))
		offset = end
		fragNum++
		if fragNum > 127 {
			return nil, fmt.Errorf("message too large: exceeds 127 follow-on fragments")
		}
	}

	return blocks, nil
}

// sendTrackedData writes data via conn.Write (which handles fragmentation)
// and tracks the data for retransmission.
func (s *SSU2Session) sendTrackedData(data []byte) error {
	seq := s.trackPending(data)
	n, err := s.conn.Write(data)
	if err != nil {
		s.removePending(seq)
		s.congestionCtrl.OnPacketLoss()
		return err
	}
	s.updateSendStats(n)
	return nil
}

// waitForCongestionWindow blocks until the congestion window allows sending size bytes.
func (s *SSU2Session) waitForCongestionWindow(size int) error {
	for !s.congestionCtrl.CanSend(size) {
		select {
		case <-s.ctx.Done():
			return ErrSessionClosed
		case <-time.After(ccPollInterval):
		}
	}
	return nil
}

// sendTrackedBlocks writes blocks to the connection and tracks for retransmission.
func (s *SSU2Session) sendTrackedBlocks(data []byte, blocks []*ssu2noise.SSU2Block) error {
	seq := s.trackPendingBlocks(data, blocks)
	if err := s.conn.WriteBlocks(blocks); err != nil {
		s.removePending(seq)
		s.congestionCtrl.OnPacketLoss()
		return err
	}
	s.updateSendStats(len(data))
	return nil
}

// updateSendStats updates bandwidth and congestion control stats after a successful send.
func (s *SSU2Session) updateSendStats(n int) {
	atomic.StoreInt64(&s.lastSendNano, time.Now().UnixNano())
	atomic.AddUint64(&s.bytesSent, uint64(n))
	s.congestionCtrl.OnPacketSent(n)
}

// trackPending stores an I2NP payload in the pending retransmission map and
// returns its sequence number.
func (s *SSU2Session) trackPending(data []byte) uint64 {
	return s.trackPendingBlocks(data, nil)
}

// trackPendingBlocks stores an I2NP payload and its pre-built blocks in the
// pending retransmission map and returns its sequence number.
func (s *SSU2Session) trackPendingBlocks(data []byte, blocks []*ssu2noise.SSU2Block) uint64 {
	seq := atomic.AddUint64(&s.pendingSeqNext, 1)
	rto := s.rttEstimator.GetRTO()
	now := time.Now()
	s.pendingMsgsMu.Lock()
	s.pendingMsgs[seq] = &pendingI2NP{
		data:     data,
		blocks:   blocks,
		sentAt:   now,
		deadline: now.Add(rto),
	}
	s.pendingMsgsMu.Unlock()
	return seq
}

// removePending deletes a pending message from the map.
func (s *SSU2Session) removePending(seq uint64) {
	s.pendingMsgsMu.Lock()
	delete(s.pendingMsgs, seq)
	s.pendingMsgsMu.Unlock()
}

// handleRetransmissions checks all pending I2NP messages and retransmits any
// that have exceeded their RTO deadline.  Returns true if the session should
// be closed (max retransmissions exceeded for at least one message).
func (s *SSU2Session) handleRetransmissions() (shouldClose bool) {
	now := time.Now()
	var toDelete []uint64
	var hadLoss bool

	s.pendingMsgsMu.Lock()
	for seq, p := range s.pendingMsgs {
		if now.Before(p.deadline) {
			continue
		}
		// Any deadline expiry indicates packet loss — signal regardless of
		// whether the retransmission itself succeeded or failed.
		hadLoss = true
		action := s.processRetransmission(p, now)
		if action == retransmitDelete || action == retransmitMaxExceeded {
			toDelete = append(toDelete, seq)
			if action == retransmitMaxExceeded {
				shouldClose = true
			}
		}
	}
	for _, seq := range toDelete {
		delete(s.pendingMsgs, seq)
	}
	s.pendingMsgsMu.Unlock()

	if hadLoss {
		s.congestionCtrl.OnRetransmissionTimeout()
	}
	return shouldClose
}

// retransmitAction indicates the result of processing a pending message for retransmission.
type retransmitAction int

const (
	retransmitOK          retransmitAction = iota // successfully retransmitted
	retransmitDelete                              // should delete due to error
	retransmitMaxExceeded                         // max retransmissions exceeded
)

// processRetransmission handles a single pending message that has exceeded its deadline.
// Must be called while holding pendingMsgsMu.
func (s *SSU2Session) processRetransmission(p *pendingI2NP, now time.Time) retransmitAction {
	if p.attempts >= s.maxRetransmit {
		return retransmitMaxExceeded
	}
	var err error
	var n int
	if len(p.blocks) > 0 {
		err = s.conn.WriteBlocks(p.blocks)
		if err == nil {
			n = len(p.data)
		}
	} else {
		n, err = s.conn.Write(p.data)
	}
	if err != nil {
		return retransmitDelete
	}
	atomic.AddUint64(&s.bytesSent, uint64(n))
	p.attempts++
	backoff := s.rttEstimator.GetRTO() * (1 << uint(p.attempts))
	if backoff > maxRetransmitBackoff {
		backoff = maxRetransmitBackoff
	}
	p.deadline = now.Add(backoff)
	return retransmitOK
}

// ackPendingBeforeTime removes pending messages sent before t and credits the
// congestion window for the freed bytes.  Called by receiveWorker to model
// peer-responsiveness as a delivery confirmation.
func (s *SSU2Session) ackPendingBeforeTime(t time.Time) {
	var ackedBytes int
	s.pendingMsgsMu.Lock()
	for seq, p := range s.pendingMsgs {
		if p.sentAt.Before(t) {
			ackedBytes += len(p.data)
			delete(s.pendingMsgs, seq)
		}
	}
	s.pendingMsgsMu.Unlock()
	if ackedBytes > 0 {
		s.congestionCtrl.OnAck(ackedBytes)
	}
}

func (s *SSU2Session) discardRemainingMessages() {
	for {
		select {
		case <-s.sendQueue:
			atomic.AddInt32(&s.sendQueueSize, -1)
		default:
			return
		}
	}
}

// ssu2ReadDeadline is the maximum time to wait for a message before checking session state.
const ssu2ReadDeadline = 5 * time.Minute

// maxI2NPMessageSize is the maximum reassembled I2NP message size (I2NP spec
// uses a 16-bit length field, ceiling is 65535 bytes).
const maxI2NPMessageSize = 65536

// receiveAction classifies the outcome of a read error for the receive loop.
type receiveAction int

const (
	receiveRetry receiveAction = iota // transient timeout / deadline, retry
	receiveFatal                      // permanent error, close session
)

// classifyReceiveError returns receiveRetry for network timeouts and
// receiveFatal for all other errors.
func classifyReceiveError(err error) receiveAction {
	if isTimeout(err) {
		return receiveRetry
	}
	return receiveFatal
}

// dispatchReceived processes a freshly-read frame: updates RTT, ACKs pending
// messages, parses the payload as an I2NP message, and delivers it to recvChan.
// Returns a non-nil error only for fatal session-ending conditions (context done).
// Parse failures are logged and silently dropped (non-fatal).
//
// Frames arrive in SSU2 short-header format (9-byte header + body) from
// conn.Read(), whether the original message was fragmented or not.
func (s *SSU2Session) dispatchReceived(frame []byte) error {
	recvAt := time.Now()
	atomic.AddUint64(&s.bytesReceived, uint64(len(frame)))

	s.updateRTTEstimate(recvAt)
	s.ackPendingBeforeTime(recvAt)

	msg := i2np.NewBaseI2NPMessage(0)
	if err := msg.UnmarshalShortI2NP(frame); err != nil {
		s.logger.WithError(err).Debug("Failed to parse I2NP message")
		return nil // non-fatal: skip malformed frame
	}
	return s.deliverMessage(msg)
}

// updateRTTEstimate updates the RTT estimate using time since last send as a rough proxy.
func (s *SSU2Session) updateRTTEstimate(recvAt time.Time) {
	lastSendNano := atomic.LoadInt64(&s.lastSendNano)
	if lastSendNano <= 0 {
		return
	}
	rtt := recvAt.Sub(time.Unix(0, lastSendNano))
	if rtt > 0 && rtt < maxRTTSample {
		s.rttEstimator.Update(rtt)
	}
}

// deliverMessage sends the message to the receive channel with timeout handling.
func (s *SSU2Session) deliverMessage(msg i2np.I2NPMessage) error {
	select {
	case s.recvChan <- msg:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	case <-time.After(100 * time.Millisecond):
		atomic.AddUint64(&s.droppedMessages, 1)
		s.logger.Warn("Receive channel full, dropping message")
		return nil
	}
}

func (s *SSU2Session) receiveWorker() {
	defer s.wg.Done()
	buf := make([]byte, maxI2NPMessageSize)

	for {
		if s.isContextCanceled() {
			return
		}
		n, action := s.readFrame(buf)
		if action == receiveFatal {
			return
		}
		if action == receiveRetry {
			continue
		}
		if err := s.dispatchReceived(buf[:n]); err != nil {
			return
		}
	}
}

// isContextCanceled checks if the session context has been canceled.
func (s *SSU2Session) isContextCanceled() bool {
	select {
	case <-s.ctx.Done():
		return true
	default:
		return false
	}
}

// readFrame reads a single frame from the connection with deadline handling.
// Returns the number of bytes read and an action indicating how to proceed.
// On success, action is -1 (proceed to dispatch). On error, action is receiveRetry or receiveFatal.
func (s *SSU2Session) readFrame(buf []byte) (int, receiveAction) {
	if err := s.conn.SetReadDeadline(time.Now().Add(ssu2ReadDeadline)); err != nil {
		s.logger.WithError(err).Error("Failed to set read deadline")
		return 0, receiveFatal
	}
	n, err := s.conn.Read(buf)
	if err != nil {
		return 0, s.handleReadError(err)
	}
	return n, -1 // proceed to dispatch
}

// handleReadError classifies a read error and returns the appropriate action.
func (s *SSU2Session) handleReadError(err error) receiveAction {
	action := classifyReceiveError(err)
	if action == receiveFatal {
		s.logger.WithError(err).Debug("Read error on SSU2 session")
	}
	return action
}

func isTimeout(err error) bool {
	type netError interface {
		Timeout() bool
	}
	if ne, ok := err.(netError); ok {
		return ne.Timeout()
	}
	return false
}
