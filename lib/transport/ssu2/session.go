package ssu2

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"golang.org/x/time/rate"
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
	*transport.SessionCore

	conn   *ssu2noise.SSU2Conn
	connMu sync.RWMutex // protects conn field (R-1 fix: upgraded to RWMutex for read-heavy access)

	// Phase 5: Reliability & congestion control (SSU2-specific fields)
	rttEstimator   *ssu2noise.RTTEstimator
	congestionCtrl *ssu2noise.CongestionController
	pendingMsgsMu  sync.Mutex
	pendingMsgs    map[uint64]*pendingI2NP
	pendingSeqNext uint64 // incremented atomically
	maxRetransmit  int
	lastSendNano   int64 // atomic unix-nano of most recent Write call

	// peerTestLimiter enforces a per-session cap on PeerTest (Bob-role) relays.
	// Burst of 3 with a sustained rate of 1/s (I2P spec allows infrequent tests).
	peerTestLimiter *rate.Limiter
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
	sessionLogger := logger.WithFields(map[string]interface{}{
		"component":   "ssu2_session",
		"remote_addr": conn.RemoteAddr().String(),
	})
	sessionLogger.Info("Creating new SSU2 session")

	rtt := ssu2noise.NewRTTEstimator()
	s := &SSU2Session{
		SessionCore:    transport.NewSessionCore(ctx, sessionLogger),
		conn:           conn,
		rttEstimator:   rtt,
		congestionCtrl: ssu2noise.NewCongestionController(rtt),
		pendingMsgs:    make(map[uint64]*pendingI2NP),
		maxRetransmit:  DefaultMaxRetransmissions,
	}
	s.peerTestLimiter = rate.NewLimiter(rate.Limit(1), 3)
	s.wireDataHandlerCallbacks()
	return s
}

// wireDataHandlerCallbacks wires protocol-level callbacks from the go-noise
// DataHandler into the SSU2Session. Called once during session construction,
// before StartWorkers(), so callbacks are active from the first data packet.
func (s *SSU2Session) wireDataHandlerCallbacks() {
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn != nil {
		conn.SetDataHandlerCallbacks(s.buildMergedCallbacks(nil))
	}
}

// buildMergedCallbacks constructs a DataHandlerCallbacks that combines
// session-local handlers (termination, clock validation) with any
// transport-level handlers supplied in extra. extra may be nil.
func (s *SSU2Session) buildMergedCallbacks(extra *BlockCallbackConfig) ssu2noise.DataHandlerCallbacks {
	cbs := ssu2noise.DataHandlerCallbacks{
		OnTermination: func(_ uint64, reason uint8, _ []byte) {
			s.Logger().WithField("termination_reason", reason).Warn("SSU2 session terminated by peer")
			s.Cancel()
		},
		OnDateTime: func(timestamp uint32) error {
			now := time.Now().Unix()
			delta := int64(timestamp) - now
			if delta < 0 {
				delta = -delta
			}
			if delta > 60 {
				s.Logger().WithField("skew_seconds", delta).Warn("SSU2 clock skew out of tolerance, closing session")
				s.Cancel()
				return oops.Errorf("clock skew %ds exceeds 60s tolerance", delta)
			}
			return nil
		},
		// OnACK: when the peer sends an explicit ACK block it means they are
		// receiving our packets. Use this as a heuristic to retire I2NP
		// messages that were sent more than 2×RTO before the ACK arrived;
		// those messages have had ample time to be delivered and ACKed at
		// the SSU2 packet layer (which the go-noise conn handles internally).
		// This prevents pendingMsgs from accumulating unbounded while full
		// per-packet ACK correlation (mapping SSU2 PN → I2NP seq) is pending.
		OnACK: func(_ *ssu2noise.SSU2Block) error {
			cutoff := time.Now().Add(-2 * s.rttEstimator.GetRTO())
			s.ackPendingBeforeTime(cutoff)
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
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn != nil {
		conn.SetDataHandlerCallbacks(s.buildMergedCallbacks(cfg))
	}
}

// mergeBlockCallbacks copies non-nil callbacks from cfg into cbs,
// leaving any already-set fields (e.g. OnTermination) untouched.
func mergeBlockCallbacks(cbs *ssu2noise.DataHandlerCallbacks, cfg *BlockCallbackConfig) {
	// Explicit nil checks for each callback field avoid generic type issues
	// with function types and interface{} nil checks.
	if cfg.OnRouterInfo != nil {
		cbs.OnRouterInfo = cfg.OnRouterInfo
	}
	if cfg.OnACK != nil {
		cbs.OnACK = cfg.OnACK
	}
	if cfg.OnDateTime != nil {
		cbs.OnDateTime = cfg.OnDateTime
	}
	if cfg.OnPeerTest != nil {
		cbs.OnPeerTest = cfg.OnPeerTest
	}
	if cfg.OnRelayRequest != nil {
		cbs.OnRelayRequest = cfg.OnRelayRequest
	}
	if cfg.OnRelayResponse != nil {
		cbs.OnRelayResponse = cfg.OnRelayResponse
	}
	if cfg.OnRelayIntro != nil {
		cbs.OnRelayIntro = cfg.OnRelayIntro
	}
	if cfg.OnNewToken != nil {
		cbs.OnNewToken = cfg.OnNewToken
	}
	if cfg.OnAddress != nil {
		cbs.OnAddress = cfg.OnAddress
	}
	if cfg.OnOptions != nil {
		cbs.OnOptions = cfg.OnOptions
	}
	if cfg.OnPathChallenge != nil {
		cbs.OnPathChallenge = cfg.OnPathChallenge
	}
	if cfg.OnPathResponse != nil {
		cbs.OnPathResponse = cfg.OnPathResponse
	}
	// H2 fix: Merge verification callbacks (VerifyRelayIntroSignature, etc.)
	if cfg.VerifyRelayIntroSignature != nil {
		cbs.VerifyRelayIntroSignature = cfg.VerifyRelayIntroSignature
	}
}

// StartWorkers launches the background send and receive goroutines.
func (s *SSU2Session) StartWorkers() {
	s.WaitGroup().Add(2)
	go s.sendWorker()
	go s.receiveWorker()
	s.Logger().Info("SSU2 session workers started")
}

// Close closes the session cleanly with a normal-close termination reason.
func (s *SSU2Session) Close() error {
	return s.CloseWithReason(ssu2noise.TerminationNormalClose)
}

// CloseWithReason closes the session with the specified termination reason code.
// A termination block is sent to the remote peer before closing the connection.
func (s *SSU2Session) CloseWithReason(reason ssu2noise.TerminationReason) error {
	var err error
	s.CloseOnce().Do(func() {
		s.Logger().WithField("reason", reason.String()).Info("Closing SSU2 session")
		// Reset pendingMsgs to free resources held by the retransmission tracker.
		// Any unconfirmed messages are dropped at this point since the session
		// is being torn down regardless (MEDIUM-1 fix).
		s.pendingMsgsMu.Lock()
		s.pendingMsgs = make(map[uint64]*pendingI2NP)
		s.pendingMsgsMu.Unlock()
		s.drainSendQueue()
		s.connMu.Lock()
		conn := s.conn
		s.connMu.Unlock()
		if conn != nil {
			err = conn.CloseWithReason(reason, nil)
		}
		s.Cancel()
		s.WaitGroup().Wait()
		s.CallCleanupCallback()
		s.Logger().Info("SSU2 session closed")
	})
	return err
}

// DetachConn clears the session's reference to the underlying connection,
// preventing Close() from closing the socket. This is used when a session
// loses a promotion race — the winner owns the socket, so the loser must
// not close it. Workers will still stop cleanly when Close() cancels the
// session context (SM-2 fix).
func (s *SSU2Session) DetachConn() {
	s.connMu.Lock()
	s.conn = nil
	s.connMu.Unlock()
}

// Conn returns the session's underlying connection, or nil if detached (R-1 fix).
// Caller must not retain the pointer across context switches.
func (s *SSU2Session) Conn() *ssu2noise.SSU2Conn {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	return s.conn
}

// RemoteAddr returns the remote address of the session's underlying connection,
// or nil if the connection is detached (R-1 fix).
func (s *SSU2Session) RemoteAddr() net.Addr {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.RemoteAddr()
}

// WriteBlocks writes raw SSU2 blocks directly to the underlying connection,
// bypassing the I2NP send queue. Used for protocol-level blocks such as PeerTest
// and Relay that must not be fragmented or queued alongside I2NP traffic.
func (s *SSU2Session) WriteBlocks(blocks []*ssu2noise.SSU2Block) error {
	// Check if conn has been detached (SM-2 fix: losing promotion race).
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn == nil {
		return ErrSessionClosed
	}
	return conn.WriteBlocks(blocks)
}

func (s *SSU2Session) drainSendQueue() {
	s.SessionCore.DrainSendQueue(transport.DefaultSendQueueDrainTimeout)
}

func (s *SSU2Session) sendWorker() {
	defer s.WaitGroup().Done()
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
	case msg := <-s.SendQueue():
		return s.handleQueuedMessage(msg)
	case <-ticker.C:
		return s.checkRetransmissions()
	case <-s.GetContext().Done():
		s.discardRemainingMessages()
		return true
	}
}

// handleQueuedMessage processes a message from the send queue.
// Returns true if the worker should exit due to an error.
func (s *SSU2Session) handleQueuedMessage(msg i2np.Message) bool {
	s.AddToSendQueueSize(-1)
	if err := s.sendWithCongestionControl(msg); err != nil {
		s.Logger().WithError(err).Error("Failed to send message")
		s.discardRemainingMessages()
		return true
	}
	return false
}

// checkRetransmissions handles the retransmission tick.
// Returns true if the worker should exit due to max retransmissions.
func (s *SSU2Session) checkRetransmissions() bool {
	if s.handleRetransmissions() {
		s.Logger().Warn("Max retransmissions exceeded, closing session")
		s.Cancel()
		return true
	}
	return false
}

// sendWithCongestionControl serializes msg as an SSU2 short-header I2NP
// message, fragments it into correctly-formatted SSU2 blocks, waits for
// congestion-window room, then writes the blocks to the conn.
func (s *SSU2Session) sendWithCongestionControl(msg i2np.Message) error {
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
func marshalI2NPShort(msg i2np.Message) ([]byte, error) {
	var body []byte
	if dc, ok := msg.(i2np.DataCarrier); ok {
		body = dc.GetData()
	} else {
		full, err := msg.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if len(full) < 16 {
			return nil, oops.Errorf("NTCP data too short: %d bytes", len(full))
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
		return nil, oops.Errorf("SSU2 short data too short: %d bytes", len(data))
	}

	// Extract header fields from SSU2 short format
	i2npType := data[0]
	messageID := binary.BigEndian.Uint32(data[1:5])
	shortExpiry := binary.BigEndian.Uint32(data[5:9])
	body := data[i2np.ShortI2NPHeaderSize:]

	firstBlock, firstBodySize, err := buildShortFirstFragment(i2npType, messageID, shortExpiry, body, maxPayload, blockTLVOverhead)
	if err != nil {
		return nil, err
	}

	blocks := []*ssu2noise.SSU2Block{firstBlock}

	followOns, err := buildShortFollowOnFragments(messageID, body, firstBodySize, maxPayload, blockTLVOverhead)
	if err != nil {
		return nil, err
	}
	blocks = append(blocks, followOns...)

	return blocks, nil
}

// buildShortFirstFragment creates the first fragment block for a fragmented SSU2 short message.
// Returns the block, the number of body bytes included, and any error.
func buildShortFirstFragment(i2npType byte, messageID, shortExpiry uint32, body []byte, maxPayload, tlvOverhead int) (*ssu2noise.SSU2Block, int, error) {
	const firstFragHeaderSize = 9 // type(1) + msgID(4) + shortExpiry(4)
	maxFirstBody := maxPayload - tlvOverhead - firstFragHeaderSize
	if maxFirstBody <= 0 {
		return nil, 0, oops.Errorf("max payload %d too small for first fragment", maxPayload)
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

	return ssu2noise.NewSSU2Block(ssu2noise.BlockTypeFirstFragment, firstData), firstBodySize, nil
}

// buildShortFollowOnFragments creates follow-on fragment blocks for the remaining body data.
func buildShortFollowOnFragments(messageID uint32, body []byte, offset, maxPayload, tlvOverhead int) ([]*ssu2noise.SSU2Block, error) {
	const followOnHeaderSize = 5 // fragInfo(1) + msgID(4)
	maxFollowBody := maxPayload - tlvOverhead - followOnHeaderSize
	if maxFollowBody <= 0 {
		return nil, oops.Errorf("max payload %d too small for follow-on fragment", maxPayload)
	}

	var blocks []*ssu2noise.SSU2Block
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
			return nil, oops.Errorf("message too large: exceeds 127 follow-on fragments")
		}
	}

	return blocks, nil
}

// waitForCongestionWindow blocks until the congestion window allows sending size bytes.
func (s *SSU2Session) waitForCongestionWindow(size int) error {
	timer := time.NewTimer(ccPollInterval)
	defer timer.Stop()
	for !s.congestionCtrl.CanSend(size) {
		select {
		case <-s.GetContext().Done():
			return ErrSessionClosed
		case <-timer.C:
			timer.Reset(ccPollInterval)
		}
	}
	return nil
}

// sendTrackedBlocks writes blocks to the connection and tracks for retransmission.
func (s *SSU2Session) sendTrackedBlocks(data []byte, blocks []*ssu2noise.SSU2Block) error {
	if s.GetContext().Err() != nil {
		return ErrSessionClosed
	}
	// Check if conn has been detached (SM-2 fix: losing promotion race).
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn == nil {
		return ErrSessionClosed
	}
	seq := s.trackPendingBlocks(data, blocks)
	if err := conn.WriteBlocks(blocks); err != nil {
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
	s.AddToBytesSent(uint64(n))
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

// retransmitCandidate holds a pending message that needs retransmission,
// collected under lock and processed after the lock is released.
type retransmitCandidate struct {
	seq     uint64
	pending *pendingI2NP
}

// handleRetransmissions checks all pending I2NP messages and retransmits any
// that have exceeded their RTO deadline.  Returns true if the session should
// be closed (max retransmissions exceeded for at least one message).
// collectExpiredPendingMessages returns all pending messages whose deadline has
// passed and a flag indicating whether any expired messages were found.
func (s *SSU2Session) collectExpiredPendingMessages(now time.Time) ([]retransmitCandidate, bool) {
	var candidates []retransmitCandidate
	var hadLoss bool
	s.pendingMsgsMu.Lock()
	for seq, p := range s.pendingMsgs {
		if now.Before(p.deadline) {
			continue
		}
		hadLoss = true
		candidates = append(candidates, retransmitCandidate{seq: seq, pending: p})
	}
	s.pendingMsgsMu.Unlock()
	return candidates, hadLoss
}

// processRetransmitCandidates iterates candidates and returns sequence numbers
// to delete. shouldClose is always false: max-retransmit no longer triggers
// session teardown (see processRetransmission for rationale).
func (s *SSU2Session) processRetransmitCandidates(candidates []retransmitCandidate, now time.Time) (toDelete []uint64, shouldClose bool) {
	for _, c := range candidates {
		action := s.processRetransmission(c.pending, now)
		if action == retransmitDelete {
			toDelete = append(toDelete, c.seq)
		}
	}
	return toDelete, false
}

// deleteExpiredMessages removes completed retransmit entries from pendingMsgs
// under lock.
func (s *SSU2Session) deleteExpiredMessages(toDelete []uint64) {
	if len(toDelete) == 0 {
		return
	}
	s.pendingMsgsMu.Lock()
	for _, seq := range toDelete {
		delete(s.pendingMsgs, seq)
	}
	s.pendingMsgsMu.Unlock()
}

func (s *SSU2Session) handleRetransmissions() (shouldClose bool) {
	now := time.Now()
	candidates, hadLoss := s.collectExpiredPendingMessages(now)
	toDelete, shouldClose := s.processRetransmitCandidates(candidates, now)
	s.deleteExpiredMessages(toDelete)
	if hadLoss {
		s.congestionCtrl.OnRetransmissionTimeout()
	}
	return shouldClose
}

// retransmitAction indicates the result of processing a pending message for retransmission.
type retransmitAction int

const (
	retransmitOK     retransmitAction = iota // successfully retransmitted
	retransmitDelete                         // should delete due to error or max attempts
)

// processRetransmission handles a single pending message that has exceeded its deadline.
// Called without holding pendingMsgsMu to avoid blocking other goroutines during network I/O.
func (s *SSU2Session) processRetransmission(p *pendingI2NP, now time.Time) retransmitAction {
	if p.attempts >= s.maxRetransmit {
		// Drop the unconfirmed entry rather than tearing down the session.
		// SSU2 packet-level reliability is handled by the go-noise conn's own
		// retransmission loop; tearing down on I2NP-level max-retransmit
		// with no ACK correlation was causing every session to self-close
		// after the first message aged out (HIGH audit finding).
		s.Logger().WithField("attempts", p.attempts).Warn(
			"I2NP message exceeded max retransmissions; dropping (delivery unconfirmed, SSU2 ACK not correlated)")
		return retransmitDelete
	}
	// Check if conn has been detached (SM-2 fix: losing promotion race).
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn == nil {
		return retransmitDelete
	}
	var err error
	var n int
	if len(p.blocks) > 0 {
		err = conn.WriteBlocks(p.blocks)
		if err == nil {
			n = len(p.data)
		}
	} else {
		n, err = conn.Write(p.data)
	}
	if err != nil {
		return retransmitDelete
	}
	s.AddToBytesSent(uint64(n))
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
	s.SessionCore.DiscardRemaining()
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
	s.AddToBytesReceived(uint64(len(frame)))

	s.updateRTTEstimate(recvAt)
	// H1 FIX: Disabled implicit ACK. The previous logic removed ALL pending messages
	// sent before the receive timestamp, which is incorrect. SSU2 requires explicit
	// ACK blocks to confirm delivery. Without proper ACK block parsing, the implicit
	// ACK was causing message loss. This is disabled until proper explicit ACK handling
	// is implemented.
	// TODO: Implement explicit ACK block parsing and only remove acknowledged messages.
	// s.ackPendingBeforeTime(recvAt)

	msg := i2np.NewBaseI2NPMessage(0)
	if err := msg.UnmarshalShortI2NP(frame); err != nil {
		s.Logger().WithError(err).Debug("Failed to parse I2NP message")
		return nil // non-fatal: skip malformed frame
	}
	if err := s.checkInboundRateLimit(msg); err != nil {
		return err
	}
	return s.deliverMessage(msg)
}

func (s *SSU2Session) checkInboundRateLimit(msg i2np.Message) error {
	if s.InboundLimiter().Allow() {
		return nil
	}
	s.Logger().WithField("message_type", msg.Type()).Warn("Inbound I2NP rate limit exceeded, closing session")
	go func() { _ = s.Close() }()
	return oops.Errorf("inbound I2NP rate limit exceeded")
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
func (s *SSU2Session) deliverMessage(msg i2np.Message) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case s.RecvChan() <- msg:
		return nil
	case <-s.GetContext().Done():
		return s.GetContext().Err()
	case <-timer.C:
		s.RecordDroppedMessage()
		s.Logger().Warn("Receive channel full, dropping message")
		return nil
	}
}

func (s *SSU2Session) receiveWorker() {
	defer s.WaitGroup().Done()
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
		// H8 FIX: Copy the buffer slice before dispatching to prevent silent data
		// corruption if UnmarshalShortI2NP retains a reference to the slice.
		// The next readFrame call will overwrite the original buffer, so we must
		// pass a copy to dispatchReceived.
		frameCopy := make([]byte, n)
		copy(frameCopy, buf[:n])
		if err := s.dispatchReceived(frameCopy); err != nil {
			return
		}
	}
}

// isContextCanceled checks if the session context has been canceled.
func (s *SSU2Session) isContextCanceled() bool {
	select {
	case <-s.GetContext().Done():
		return true
	default:
		return false
	}
}

// readFrame reads a single frame from the connection with deadline handling.
// Returns the number of bytes read and an action indicating how to proceed.
// On success, action is -1 (proceed to dispatch). On error, action is receiveRetry or receiveFatal.
func (s *SSU2Session) readFrame(buf []byte) (int, receiveAction) {
	// Check if conn has been detached (SM-2 fix: losing promotion race).
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn == nil {
		return 0, receiveFatal
	}
	if err := conn.SetReadDeadline(time.Now().Add(ssu2ReadDeadline)); err != nil {
		s.Logger().WithError(err).Error("Failed to set read deadline")
		return 0, receiveFatal
	}
	n, err := conn.Read(buf)
	if err != nil {
		return 0, s.handleReadError(err)
	}
	return n, -1 // proceed to dispatch
}

// handleReadError classifies a read error and returns the appropriate action.
func (s *SSU2Session) handleReadError(err error) receiveAction {
	action := classifyReceiveError(err)
	if action == receiveFatal {
		s.Logger().WithError(err).Debug("Read error on SSU2 session")
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
