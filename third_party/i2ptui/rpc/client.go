// Package rpc wraps the go-i2pcontrol library into a polling-based snapshot
// model for use with Bubble Tea commands.
package rpc

import (
	"fmt"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	i2pcontrol "github.com/go-i2p/go-i2pcontrol"
)

const ntcp2ActivePeersStat = "tcp.activePeers"

// RouterSnapshot holds a point-in-time snapshot of router state.
type RouterSnapshot struct {
	// Info
	Status               string
	NetStatus            string
	Version              string
	RouterHash           string
	Uptime               int64
	IncomingBW           int
	OutgoingBW           int
	KnownPeers           int
	ParticipatingTunnels int
	Reseeding            bool

	// Stats
	SendBps              int
	ReceiveBps           int
	SendBpsHourAvg       int
	ReceiveBpsHourAvg    int
	ParticipatingAvg     int
	ParticipatingHourAvg int
	ExplBuildSuccess     int
	ExplBuildReject      int
	ExplBuildExpire      int
	ClientBuildSuccess   int
	BuildRequestTime     float64

	// Percentages
	ExplBuildSuccessPct int
	ExplBuildRejectPct  int
	ExplBuildExpirePct  int

	// Transport sessions
	NTCP2Sessions int
	SSU2Sessions  int

	// Settings
	Upnp string

	// Metadata
	FetchedAt time.Time
	Err       error
}

// UptimeDuration returns the router uptime as a time.Duration.
func (s RouterSnapshot) UptimeDuration() time.Duration {
	return time.Duration(s.Uptime) * time.Millisecond
}

// TickMsg signals that a polling interval has elapsed.
type TickMsg time.Time

// authToken holds the API token for custom RPC calls.
// Guarded by tokenMu; written once in Setup, read by readSetting/WriteSetting.
var (
	authToken string
	tokenMu   sync.RWMutex
)

// Setup initializes the I2PControl RPC connection and authenticates.
func Setup(host, port, path, password, cert string) error {
	if cert != "" {
		if err := i2pcontrol.InitializeWithSelfSignedCert(host, port, path, cert); err != nil {
			return fmt.Errorf("init with cert: %w", err)
		}
	} else {
		i2pcontrol.Initialize(host, port, path)
	}
	if _, err := i2pcontrol.Authenticate(password); err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}
	if err := captureToken(password); err != nil {
		return fmt.Errorf("capture token: %w", err)
	}
	return nil
}

// captureToken authenticates and stores the API token for subsequent calls.
func captureToken(password string) error {
	resp, err := i2pcontrol.Call("Authenticate", map[string]interface{}{
		"API":      1,
		"Password": password,
	})
	if err != nil {
		return err
	}
	tok, ok := resp["Token"].(string)
	if !ok {
		return fmt.Errorf("missing token in response")
	}
	tokenMu.Lock()
	authToken = tok
	tokenMu.Unlock()
	return nil
}

// PollTick returns a tea.Cmd that sends a TickMsg after the interval.
func PollTick(interval time.Duration) tea.Cmd {
	return tea.Tick(interval, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// FetchSnapshotCmd is a tea.Cmd that fetches a RouterSnapshot.
func FetchSnapshotCmd() tea.Msg {
	return FetchSnapshot()
}

// FetchSnapshot gathers current router state into a RouterSnapshot.
func FetchSnapshot() (snap RouterSnapshot) {
	snap = RouterSnapshot{FetchedAt: time.Now()}
	defer func() {
		if r := recover(); r != nil {
			snap.Err = fmt.Errorf("rpc snapshot panic: %v", r)
		}
	}()

	snap.Status = fetchString(i2pcontrol.Status)
	snap.NetStatus = fetchString(i2pcontrol.NetStatus)
	snap.Version = fetchString(i2pcontrol.Version)
	snap.RouterHash = fetchRouterHash()
	snap.Uptime = fetchInt64(i2pcontrol.UpTime)
	snap.IncomingBW = fetchInt(i2pcontrol.IncomingBW)
	snap.OutgoingBW = fetchInt(i2pcontrol.OutgoingBw)
	snap.KnownPeers = fetchInt(i2pcontrol.KnownPeers)
	snap.ParticipatingTunnels = fetchInt(i2pcontrol.ParticipatingTunnels)
	snap.Reseeding = fetchBool(i2pcontrol.Reseeding)

	snap.SendBps = fetchInt(i2pcontrol.SendBps)
	snap.ReceiveBps = fetchInt(i2pcontrol.ReceiveBps)
	snap.SendBpsHourAvg = fetchInt(i2pcontrol.SendBpsHourAverage)
	snap.ReceiveBpsHourAvg = fetchInt(i2pcontrol.ReceiveBpsHourAverage)
	snap.ParticipatingAvg = fetchInt(i2pcontrol.ParticipatingAverageTunnels)
	snap.ParticipatingHourAvg = fetchInt(i2pcontrol.ParticipatingHourAverageTunnels)
	snap.ExplBuildSuccess = fetchInt(i2pcontrol.ExploratoryBuildSuccess)
	snap.ExplBuildReject = fetchInt(i2pcontrol.ExploratoryBuildReject)
	snap.ExplBuildExpire = fetchInt(i2pcontrol.ExploratoryBuildExpire)
	snap.ClientBuildSuccess = fetchInt(i2pcontrol.ClientBuildSuccess)
	snap.BuildRequestTime = fetchFloat64(i2pcontrol.BuildRequestTime)

	snap.ExplBuildSuccessPct = fetchInt(i2pcontrol.ExploratoryBuildSuccessPercentage)
	snap.ExplBuildRejectPct = fetchInt(i2pcontrol.ExploratoryBuildRejectPercentage)
	snap.ExplBuildExpirePct = fetchInt(i2pcontrol.ExploratoryBuildExpirePercentage)

	snap.NTCP2Sessions = fetchInt(func() (int, error) { return i2pcontrol.RateStat(ntcp2ActivePeersStat, 60000) })
	snap.SSU2Sessions = fetchInt(func() (int, error) { return i2pcontrol.RateStat("udp.activePeers", 60000) })

	snap.Upnp = fetchString(i2pcontrol.Upnp)

	return snap
}

// RestartGraceful wraps the i2pcontrol graceful restart RPC call.
func RestartGraceful() (string, error) {
	return i2pcontrol.RestartGraceful()
}

// RouterSettings holds the current router configuration values.
type RouterSettings struct {
	BWIn    string
	BWOut   string
	BWShare string
	Upnp    string
	Err     error
}

// ReadSettings fetches the current settings via NetworkSetting.
func ReadSettings() RouterSettings {
	s := RouterSettings{}
	s.BWIn = readSetting("i2p.router.net.bw.in")
	s.BWOut = readSetting("i2p.router.net.bw.out")
	s.BWShare = readSetting("i2p.router.net.bw.share")
	s.Upnp = readSetting("i2p.router.net.upnp")
	return s
}

// readSetting fetches a single NetworkSetting value by key.
func readSetting(key string) string {
	tokenMu.RLock()
	tok := authToken
	tokenMu.RUnlock()
	resp, err := i2pcontrol.Call("NetworkSetting", map[string]interface{}{
		key:     nil,
		"Token": tok,
	})
	if err != nil {
		return "N/A"
	}
	if v, ok := resp[key]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return "N/A"
}

// WriteSetting sets a single NetworkSetting key to the given value.
func WriteSetting(key, value string) error {
	tokenMu.RLock()
	tok := authToken
	tokenMu.RUnlock()
	_, err := i2pcontrol.Call("NetworkSetting", map[string]interface{}{
		key:     value,
		"Token": tok,
	})
	return err
}

// Restart wraps the i2pcontrol immediate restart RPC call.
func Restart() (string, error) {
	return i2pcontrol.Restart()
}

// ShutdownGraceful wraps the i2pcontrol graceful shutdown RPC call.
func ShutdownGraceful() (string, error) {
	return i2pcontrol.ShutdownGraceful()
}

// Shutdown wraps the i2pcontrol immediate shutdown RPC call.
func Shutdown() (string, error) {
	return i2pcontrol.Shutdown()
}

// FindUpdates wraps the i2pcontrol update check RPC call.
func FindUpdates() (string, error) {
	found, err := i2pcontrol.FindUpdates()
	if err != nil {
		return "", err
	}
	if found {
		return "Update available", nil
	}
	return "No updates available", nil
}

// fetchString calls fn and returns "N/A" on error.
func fetchString(fn func() (string, error)) (out string) {
	out = "N/A"
	defer func() {
		_ = recover()
	}()
	v, err := fn()
	if err != nil {
		return out
	}
	out = v
	return out
}

// fetchInt calls fn and returns 0 on error.
func fetchInt(fn func() (int, error)) (out int) {
	defer func() {
		_ = recover()
	}()
	v, err := fn()
	if err != nil {
		return out
	}
	out = v
	return out
}

// fetchInt64 calls fn and returns 0 on error.
func fetchInt64(fn func() (int64, error)) (out int64) {
	defer func() {
		_ = recover()
	}()
	v, err := fn()
	if err != nil {
		return out
	}
	out = v
	return out
}

// fetchFloat64 calls fn and returns 0 on error.
func fetchFloat64(fn func() (float64, error)) (out float64) {
	defer func() {
		_ = recover()
	}()
	v, err := fn()
	if err != nil {
		return out
	}
	out = v
	return out
}

// fetchBool calls fn and returns false on error.
func fetchBool(fn func() (bool, error)) (out bool) {
	defer func() {
		_ = recover()
	}()
	v, err := fn()
	if err != nil {
		return out
	}
	out = v
	return out
}

// fetchRouterHash retrieves the local public router hash.
func fetchRouterHash() string {
	defer func() {
		_ = recover()
	}()
	tokenMu.RLock()
	tok := authToken
	tokenMu.RUnlock()
	resp, err := i2pcontrol.Call("RouterInfo", map[string]interface{}{
		"i2p.router.hash": nil,
		"Token":           tok,
	})
	if err != nil {
		return "N/A"
	}
	if v, ok := resp["i2p.router.hash"]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return "N/A"
}
