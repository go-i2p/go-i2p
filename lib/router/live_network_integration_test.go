//go:build integration

package router

import (
	"context"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/netdb"
	ssu2 "github.com/go-i2p/go-i2p/lib/transport/ssu2"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/require"
)

const (
	liveNetworkStartupAttempts       = 3
	liveNetworkWaitForPeersTimeout   = 90 * time.Second
	liveNetworkWaitForInboundTimeout = 75 * time.Second
	liveNetworkWaitForPublishTimeout = 80 * time.Second
	liveNetworkPublishAttemptTimeout = 90 * time.Second
	liveNetworkPollInterval          = 2 * time.Second
	liveNetworkAttemptDelay          = 3 * time.Second
	liveNetworkRetryAttempts         = 4
)

func TestLiveNetworkBootstrapAndInterop(t *testing.T) {
	requireLiveNetworkIntegration(t)
	sources := discoverLiveInteropSources(t)

	r := startLiveNetworkRouterForTest(t)
	db := r.GetNetDB()
	require.NotNil(t, db, "netdb should be initialized")

	allPeers, diag := waitForPeersWithRetry(t, db, 12, liveNetworkWaitForPeersTimeout)
	t.Logf("live netdb bootstrap diagnostics: %s", diag)
	require.GreaterOrEqual(t, len(allPeers), 12, "live bootstrap did not discover enough peers")

	overlap := liveInteropOverlap(allPeers, sources)
	t.Logf("peer interop diagnostics: total=%d java_source=%d java_seen=%d i2pd_source=%d i2pd_seen=%d samples=[%s]",
		len(allPeers), len(sources.JavaPeers), overlap.JavaMatches, len(sources.I2PDPeers), overlap.I2PDMatches, strings.Join(overlap.Samples, " | "))

	require.GreaterOrEqual(t, overlap.JavaMatches, 1,
		"expected at least one router from %s to appear in live netdb snapshot; diagnostics=%s", sources.JavaLabel, overlap.DiagnosticSummary())
	require.GreaterOrEqual(t, overlap.I2PDMatches, 1,
		"expected at least one router from %s to appear in live netdb snapshot; diagnostics=%s", sources.I2PDLabel, overlap.DiagnosticSummary())
}

func TestLiveNetworkPublishRouterInfo(t *testing.T) {
	requireLiveNetworkIntegration(t)

	r := startLiveNetworkRouterForTest(t)
	db := r.GetNetDB()
	require.NotNil(t, db, "netdb should be initialized")

	_, peerDiag := waitForPeersWithRetry(t, db, 8, liveNetworkWaitForPeersTimeout)
	t.Logf("routerinfo publish precondition peers: %s", peerDiag)

	backgroundPublisher := r.GetPublisher()
	require.NotNil(t, backgroundPublisher, "publisher should be initialized after router startup")
	require.NotNil(t, r.routerInfoProv, "routerinfo provider should be initialized after router startup")
	require.NotNil(t, r.transports, "transport muxer should be initialized after router startup")
	require.NotNil(t, r.tunnelManager, "tunnel manager should be initialized after router startup")

	// Use a dedicated one-shot publisher for this test path so the log output
	// reflects whether Java I2P accepted and ACKed this go-i2p RouterInfo.
	tracingTransport := &liveTracingSessionProvider{
		t:     t,
		inner: &publisherTransportAdapter{muxer: r.transports},
	}
	testPublisher := netdb.NewPublisher(
		&publisherNetDBAdapter{db: db},
		r.tunnelManager.GetOutboundPool(),
		tracingTransport,
		r.routerInfoProv,
		netdb.DefaultPublisherConfig(),
	)
	if r.lookupClient != nil {
		testPublisher.SetLookupTransport(r.lookupClient)
	}
	testPublisher.SetInboundPool(r.tunnelManager.GetInboundPool())

	// FORCE_TARGET_ROUTER: test-only hook that pins publication to a single
	// known-controlled router for Java-side diagnosis. The env var is read here
	// (in test code) and injected via the test-only Publisher API so that
	// production code never touches os.Getenv.
	if rawTarget := strings.TrimSpace(os.Getenv("FORCE_TARGET_ROUTER")); rawTarget != "" {
		if rawBytes, decErr := i2pbase64.DecodeString(rawTarget); decErr == nil && len(rawBytes) == 32 {
			var forcedHash common.Hash
			copy(forcedHash[:], rawBytes)
			testPublisher.SetForceTargetHash(forcedHash)
			t.Logf("FORCE_TARGET_ROUTER: forcing publication target to %x", forcedHash[:8])
		} else {
			t.Logf("FORCE_TARGET_ROUTER: ignoring invalid value %q (decode error: %v)", rawTarget, decErr)
		}
	}

	// Wire a Kademlia resolver so the forced target can be looked up from the
	// network when not yet present in local NetDB.
	if r.lookupClient != nil {
		ourHash := common.Hash{}
		if ri, riErr := r.routerInfoProv.GetRouterInfo(); riErr == nil {
			if h, hErr := ri.IdentHash(); hErr == nil {
				ourHash = h
			}
		}
		kadResolver := netdb.NewKademliaResolverWithTransport(
			&publisherNetDBAdapter{db: db},
			r.tunnelManager.GetOutboundPool(),
			r.lookupClient,
			ourHash,
		)
		testPublisher.SetForceTargetResolver(kadResolver)
	}
	if inboundPool := r.tunnelManager.GetInboundPool(); inboundPool != nil {
		poolStats := inboundPool.GetPoolStats()
		t.Logf("routerinfo publish inbound pool stats before wait: total=%d active=%d building=%d failed=%d near_expiry=%d",
			poolStats.Total,
			poolStats.Active,
			poolStats.Building,
			poolStats.Failed,
			poolStats.NearExpiry,
		)
	}
	inboundDiag := waitForActiveTunnels(r.tunnelManager.GetInboundPool(), 1, liveNetworkWaitForInboundTimeout)
	t.Logf("routerinfo publish inbound precondition: %s", inboundDiag)
	if inboundPool := r.tunnelManager.GetInboundPool(); inboundPool != nil {
		poolStats := inboundPool.GetPoolStats()
		t.Logf("routerinfo publish inbound pool stats after wait: total=%d active=%d building=%d failed=%d near_expiry=%d",
			poolStats.Total,
			poolStats.Active,
			poolStats.Building,
			poolStats.Failed,
			poolStats.NearExpiry,
		)
	}

	if r.messageRouter != nil {
		r.messageRouter.GetProcessor().SetDeliveryStatusHandler(testPublisher)
		t.Cleanup(func() {
			if current := r.GetPublisher(); current != nil {
				r.messageRouter.GetProcessor().SetDeliveryStatusHandler(current)
			}
		})
	}

	ri, err := r.routerInfoProv.GetRouterInfo()
	require.NoError(t, err, "failed to get local routerinfo for publication")
	logLiveRouterInfoForPublish(t, *ri)

	preStats := testPublisher.GetStats()
	t.Logf("routerinfo publish pre-stats: publish_ok=%d publish_fail=%d send_ok=%d send_fail=%d verify_ok=%d verify_fail=%d ack_ok=%d ack_unexpected=%d",
		preStats.RouterInfoPublishSuccess,
		preStats.RouterInfoPublishFail,
		preStats.RouterInfoSendSuccess,
		preStats.RouterInfoSendFail,
		preStats.RouterInfoVerifySuccess,
		preStats.RouterInfoVerifyFail,
		preStats.ReplyTokenAckReceived,
		preStats.ReplyTokenAckUnexpected,
	)

	publishDiag, err := retryWithDiagnostics("publish_routerinfo", 1, liveNetworkAttemptDelay, func() error {
		before := testPublisher.GetStats()
		done := make(chan error, 1)
		go func() {
			done <- testPublisher.PublishRouterInfo(*ri)
		}()

		var err error
		select {
		case err = <-done:
		case <-time.After(liveNetworkPublishAttemptTimeout):
			after := testPublisher.GetStats()
			dumpPath, dumpErr := writeGoroutineDump("routerinfo-publish-timeout-")
			if dumpErr != nil {
				t.Logf("routerinfo publish timeout goroutine dump failed: %v", dumpErr)
			} else {
				t.Logf("routerinfo publish timeout goroutine dump: %s", dumpPath)
			}
			t.Logf("routerinfo publish attempt timeout after %s: publish_ok=+%d publish_fail=+%d send_ok=+%d send_fail=+%d verify_ok=+%d verify_fail=+%d ack_ok=+%d ack_unexpected=+%d",
				liveNetworkPublishAttemptTimeout,
				after.RouterInfoPublishSuccess-before.RouterInfoPublishSuccess,
				after.RouterInfoPublishFail-before.RouterInfoPublishFail,
				after.RouterInfoSendSuccess-before.RouterInfoSendSuccess,
				after.RouterInfoSendFail-before.RouterInfoSendFail,
				after.RouterInfoVerifySuccess-before.RouterInfoVerifySuccess,
				after.RouterInfoVerifyFail-before.RouterInfoVerifyFail,
				after.ReplyTokenAckReceived-before.ReplyTokenAckReceived,
				after.ReplyTokenAckUnexpected-before.ReplyTokenAckUnexpected,
			)
			return fmt.Errorf("routerinfo publish attempt timed out after %s", liveNetworkPublishAttemptTimeout)
		}

		after := testPublisher.GetStats()
		t.Logf("routerinfo publish attempt delta: publish_ok=+%d publish_fail=+%d send_ok=+%d send_fail=+%d verify_ok=+%d verify_fail=+%d ack_ok=+%d ack_unexpected=+%d",
			after.RouterInfoPublishSuccess-before.RouterInfoPublishSuccess,
			after.RouterInfoPublishFail-before.RouterInfoPublishFail,
			after.RouterInfoSendSuccess-before.RouterInfoSendSuccess,
			after.RouterInfoSendFail-before.RouterInfoSendFail,
			after.RouterInfoVerifySuccess-before.RouterInfoVerifySuccess,
			after.RouterInfoVerifyFail-before.RouterInfoVerifyFail,
			after.ReplyTokenAckReceived-before.ReplyTokenAckReceived,
			after.ReplyTokenAckUnexpected-before.ReplyTokenAckUnexpected,
		)
		return err
	})
	t.Logf("routerinfo publish diagnostics: %s", publishDiag)
	if err != nil {
		// No ACK received means the Java floodfill did not accept the DSM.
		// send_ok > 0 only means bytes left our socket — it is NOT proof that
		// Java I2P stored the go-i2p RouterInfo.
		statsAfterErr := testPublisher.GetStats()
		t.Logf("routerinfo publish failed: send_ok=+%d send_fail=+%d ack_ok=+%d ack_unexpected=+%d error=%v",
			statsAfterErr.RouterInfoSendSuccess-preStats.RouterInfoSendSuccess,
			statsAfterErr.RouterInfoSendFail-preStats.RouterInfoSendFail,
			statsAfterErr.ReplyTokenAckReceived-preStats.ReplyTokenAckReceived,
			statsAfterErr.ReplyTokenAckUnexpected-preStats.ReplyTokenAckUnexpected,
			err,
		)
		require.NoError(t, err, "Java floodfill did not acknowledge the go-i2p RouterInfo DatabaseStore message")
	}

	postStats := testPublisher.GetStats()
	t.Logf("routerinfo publish post-stats: publish_ok=%d publish_fail=%d send_ok=%d send_fail=%d ack_ok=%d ack_unexpected=%d",
		postStats.RouterInfoPublishSuccess,
		postStats.RouterInfoPublishFail,
		postStats.RouterInfoSendSuccess,
		postStats.RouterInfoSendFail,
		postStats.ReplyTokenAckReceived,
		postStats.ReplyTokenAckUnexpected,
	)
	require.Greater(t,
		postStats.ReplyTokenAckReceived,
		preStats.ReplyTokenAckReceived,
		"expected at least one DeliveryStatus ACK from a floodfill after RouterInfo publication",
	)
}

func TestLiveNetworkPublishLeaseSet(t *testing.T) {
	requireLiveNetworkIntegration(t)

	r := startLiveNetworkRouterForTest(t)
	db := r.GetNetDB()
	require.NotNil(t, db, "netdb should be initialized")

	_, peerDiag := waitForPeersWithRetry(t, db, 8, liveNetworkWaitForPeersTimeout)
	t.Logf("leaseset publish precondition peers: %s", peerDiag)

	publisher := r.GetPublisher()
	require.NotNil(t, publisher, "publisher should be initialized after router startup")

	session, leaseSetBytes := createLiveLeaseSetForPublish(t)
	require.NotNil(t, session, "session should be created")

	destBytes, err := session.Destination().Bytes()
	require.NoError(t, err, "destination hash should be available")
	destHash := common.HashData(destBytes)

	publishDiag, err := retryWithDiagnostics("publish_leaseset", liveNetworkRetryAttempts, liveNetworkAttemptDelay, func() error {
		return publisher.PublishLeaseSet(destHash, leaseSetBytes)
	})
	t.Logf("leaseset publish diagnostics: %s", publishDiag)
	require.NoError(t, err, "leaseset publish operation failed")

	require.Eventually(t, func() bool {
		isOwn := db.IsOwnLeaseSet(destHash)
		count := db.GetLeaseSetCount()
		t.Logf("leaseset state: own=%v total_leasesets=%d dest=%s", isOwn, count, hashPrefix(destHash))
		return isOwn && count > 0
	}, liveNetworkWaitForPublishTimeout, liveNetworkPollInterval,
		"published leaseset was not persisted in local netdb as own leaseset within timeout")
}

type liveInteropSources struct {
	JavaLabel string
	I2PDLabel string
	JavaPeers map[string]router_info.RouterInfo
	I2PDPeers map[string]router_info.RouterInfo
}

type liveInteropOverlapSummary struct {
	JavaMatches int
	I2PDMatches int
	Samples     []string
}

func (s liveInteropOverlapSummary) DiagnosticSummary() string {
	return fmt.Sprintf("java_matches=%d i2pd_matches=%d samples=%s", s.JavaMatches, s.I2PDMatches, strings.Join(s.Samples, " | "))
}

func waitForPeersWithRetry(t *testing.T, db *netdb.StdNetDB, minPeers int, timeout time.Duration) ([]router_info.RouterInfo, string) {
	t.Helper()

	start := time.Now()
	var snapshots []string

	for {
		peers := db.GetAllRouterInfos()
		snapshots = append(snapshots, fmt.Sprintf("t+%s peers=%d", time.Since(start).Round(time.Second), len(peers)))
		if len(peers) >= minPeers {
			return peers, strings.Join(snapshots, ", ")
		}

		if time.Since(start) >= timeout {
			return peers, strings.Join(snapshots, ", ")
		}

		time.Sleep(liveNetworkPollInterval)
	}
}

func waitForActiveTunnels(pool *tunnel.Pool, minReady int, timeout time.Duration) string {
	start := time.Now()
	var snapshots []string

	for {
		active := 0
		if pool != nil {
			active = len(pool.GetActiveTunnels())
		}
		snapshots = append(snapshots, fmt.Sprintf("t+%s ready=%d", time.Since(start).Round(time.Second), active))
		if active >= minReady {
			return strings.Join(snapshots, ", ")
		}

		if time.Since(start) >= timeout {
			return strings.Join(snapshots, ", ")
		}

		time.Sleep(liveNetworkPollInterval)
	}
}

func startLiveNetworkRouterForTest(t *testing.T) *Router {
	t.Helper()

	var diagnostics []string

	for attempt := 1; attempt <= liveNetworkStartupAttempts; attempt++ {
		cfg := config.DefaultRouterConfig()
		cfg.WorkingDir = t.TempDir()
		cfg.BaseDir = cfg.WorkingDir
		cfg.NetDB.Path = cfg.WorkingDir + "/netDb"
		cfg.I2CP.Enabled = false
		cfg.I2PControl.Enabled = false
		cfg.Bootstrap.BootstrapType = "auto"
		cfg.Bootstrap.LowPeerThreshold = 4
		cfg.Bootstrap.LocalNetDBPaths = preferredLiveNetDBPaths()

		r, err := CreateRouter(cfg)
		if err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf("attempt=%d create_error=%q", attempt, err.Error()))
			if attempt < liveNetworkStartupAttempts {
				time.Sleep(liveNetworkAttemptDelay)
			}
			continue
		}

		if err := r.Start(); err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf("attempt=%d start_error=%q bootstrap_type=%s low_peer_threshold=%d", attempt, err.Error(), cfg.Bootstrap.BootstrapType, cfg.Bootstrap.LowPeerThreshold))
			_ = r.Close()
			if attempt < liveNetworkStartupAttempts {
				time.Sleep(liveNetworkAttemptDelay)
			}
			continue
		}

		t.Cleanup(func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := r.StopWithContext(stopCtx); err != nil {
				t.Logf("router stop timed out during cleanup: %v", err)
			}
			require.NoError(t, r.Close(), "router close failed during cleanup")
		})

		if len(diagnostics) > 0 {
			t.Logf("live router startup retries before success: %s", strings.Join(diagnostics, " | "))
		}
		return r
	}

	t.Fatalf("failed to start live-network router after %d attempts: %s", liveNetworkStartupAttempts, strings.Join(diagnostics, " | "))
	return nil
}

func retryWithDiagnostics(operation string, attempts int, delay time.Duration, fn func() error) (string, error) {
	if attempts < 1 {
		attempts = 1
	}

	var parts []string
	var lastErr error

	for i := 1; i <= attempts; i++ {
		err := fn()
		if err == nil {
			parts = append(parts, fmt.Sprintf("%s attempt=%d status=ok", operation, i))
			return strings.Join(parts, "; "), nil
		}

		lastErr = err
		parts = append(parts, fmt.Sprintf("%s attempt=%d status=err error=%q", operation, i, err.Error()))
		if i < attempts {
			time.Sleep(delay)
		}
	}

	return strings.Join(parts, "; "), fmt.Errorf("%s failed after %d attempts: %w", operation, attempts, lastErr)
}

func writeGoroutineDump(prefix string) (string, error) {
	f, err := os.CreateTemp("", prefix+"*.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()

	if err := pprof.Lookup("goroutine").WriteTo(f, 2); err != nil {
		return "", err
	}

	return f.Name(), nil
}

func createLiveLeaseSetForPublish(t *testing.T) (*i2cp.Session, []byte) {
	t.Helper()

	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err, "failed to create destination keystore for leaseset publication")

	session, err := i2cp.NewSession(1, keyStore.Destination(), i2cp.DefaultSessionConfig(), keyStore.SigningPrivateKey(), keyStore.EncryptionPrivateKey(), keyStore.IdentityPadding())
	require.NoError(t, err, "failed to create i2cp session for leaseset publication")

	pool := tunnel.NewTunnelPool(&liveNetworkNoopPeerSelector{})
	pool.AddTunnel(&tunnel.TunnelState{
		ID:        tunnel.TunnelID(1),
		Hops:      []common.Hash{testLiveHash(0x11), testLiveHash(0x22)},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
		IsInbound: true,
	})
	session.SetInboundPool(pool)
	t.Cleanup(pool.Stop)

	leaseSetBytes, err := session.CreateLeaseSet()
	require.NoError(t, err, "failed to construct leaseset for live publish")
	require.NotEmpty(t, leaseSetBytes, "created leaseset must not be empty")

	return session, leaseSetBytes
}

func requireLiveNetworkIntegration(t *testing.T) {
	t.Helper()

	if os.Getenv("GO_I2P_INTEGRATION") == "" {
		t.Skip("skipping live network integration test; set GO_I2P_INTEGRATION=1")
	}
}

func discoverLiveInteropSources(t *testing.T) liveInteropSources {
	t.Helper()

	paths := preferredLiveNetDBPaths()
	require.GreaterOrEqual(t, len(paths), 2, "expected both Java and i2pd local netDb paths to be present")

	javaPeers := loadLocalNetDBPeers(t, paths[0])
	i2pdPeers := loadLocalNetDBPeers(t, paths[1])

	require.NotEmpty(t, javaPeers, "expected peers in %s", paths[0])
	require.NotEmpty(t, i2pdPeers, "expected peers in %s", paths[1])

	return liveInteropSources{
		JavaLabel: paths[0],
		I2PDLabel: paths[1],
		JavaPeers: javaPeers,
		I2PDPeers: i2pdPeers,
	}
}

func preferredLiveNetDBPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	candidates := []string{
		filepath.Join(home, ".i2p", "netDb"),
		filepath.Join(home, "i2p", "netDb"),
	}

	paths := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			paths = append(paths, candidate)
		}
	}
	return paths
}

func loadLocalNetDBPeers(t *testing.T, path string) map[string]router_info.RouterInfo {
	t.Helper()

	result := make(map[string]router_info.RouterInfo)
	err := filepath.WalkDir(path, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry == nil || entry.IsDir() || !strings.HasSuffix(filePath, ".dat") || !strings.Contains(filePath, "routerInfo-") {
			return nil
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil
		}

		peer, _, err := router_info.ReadRouterInfo(data)
		if err != nil {
			return nil
		}
		if !bootstrap.HasDirectConnectivity(peer) {
			return nil
		}
		if err := bootstrap.ValidateRouterInfo(peer); err != nil {
			return nil
		}
		if err := bootstrap.VerifyRouterInfoSignature(peer); err != nil {
			return nil
		}

		hash, err := peer.IdentHash()
		if err != nil {
			return nil
		}
		result[hash.String()] = peer
		return nil
	})
	require.NoError(t, err, "failed to load local netDb peers from %s", path)
	return result
}

func liveInteropOverlap(peers []router_info.RouterInfo, sources liveInteropSources) liveInteropOverlapSummary {
	result := liveInteropOverlapSummary{Samples: make([]string, 0, 8)}

	for _, peer := range peers {
		hash, err := peer.IdentHash()
		if err != nil {
			continue
		}
		key := hash.String()
		version := routerInfoOptionString(peer, "router.version")
		caps := string(peer.RouterCapabilities())

		if _, ok := sources.JavaPeers[key]; ok {
			result.JavaMatches++
			if len(result.Samples) < 8 {
				result.Samples = append(result.Samples, fmt.Sprintf("java hash=%s ver=%q caps=%q", hashPrefix(hash), version, caps))
			}
		}
		if _, ok := sources.I2PDPeers[key]; ok {
			result.I2PDMatches++
			if len(result.Samples) < 8 {
				result.Samples = append(result.Samples, fmt.Sprintf("i2pd hash=%s ver=%q caps=%q", hashPrefix(hash), version, caps))
			}
		}
	}

	return result
}

func routerInfoOptionString(ri router_info.RouterInfo, key string) string {
	k, err := common.ToI2PString(key)
	if err != nil {
		return ""
	}
	v := ri.Options().Values().Get(k)
	if v == nil {
		return ""
	}
	s, err := v.Data()
	if err != nil {
		return ""
	}
	return s
}

func logLiveRouterInfoForPublish(t *testing.T, ri router_info.RouterInfo) {
	var publishedText string
	if published := ri.Published(); published != nil {
		publishedAt := published.Time()
		publishedText = fmt.Sprintf("%s age=%s", publishedAt.UTC().Format(time.RFC3339), time.Since(publishedAt).Round(time.Second))
	} else {
		publishedText = "<nil>"
	}

	t.Logf("routerinfo under test: published=%s caps=%q version=%q addr_count=%d",
		publishedText,
		string(ri.RouterCapabilities()),
		routerInfoOptionString(ri, "router.version"),
		len(ri.RouterAddresses()),
	)

	for index, addr := range ri.RouterAddresses() {
		if addr == nil {
			t.Logf("routerinfo addr[%d]: <nil>", index)
			continue
		}

		host := ""
		if addr.CheckOption(router_address.HOST_OPTION_KEY) {
			if hostStr := addr.HostString(); hostStr != nil {
				if hostData, err := hostStr.Data(); err == nil {
					host = hostData
				}
			}
		}

		port := ""
		if addr.CheckOption(router_address.PORT_OPTION_KEY) {
			if portStr := addr.PortString(); portStr != nil {
				if portData, err := portStr.Data(); err == nil {
					port = portData
				}
			}
		}

		caps := ""
		if addr.CheckOption(router_address.CAPS_OPTION_KEY) {
			if capsStr := addr.CapsString(); capsStr != nil {
				if capsData, err := capsStr.Data(); err == nil {
					caps = capsData
				}
			}
		}

		t.Logf("routerinfo addr[%d]: style=%q cost=%d host=%q port=%q caps=%q introducers=%d",
			index,
			addr.TransportStyle(),
			addr.Cost(),
			host,
			port,
			caps,
			len(ssu2.ExtractIntroducers(addr)),
		)
	}
}

type liveNetworkNoopPeerSelector struct{}

func (s *liveNetworkNoopPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	return nil, nil
}

func testLiveHash(fill byte) common.Hash {
	var hash common.Hash
	for i := range hash {
		hash[i] = fill
	}
	return hash
}

func hashPrefix(hash common.Hash) string {
	s := hash.String()
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

// liveTracingSessionProvider wraps publish sessions and emits deterministic
// test logs for DatabaseStore reply-route fields right before send.
type liveTracingSessionProvider struct {
	t     *testing.T
	inner netdb.SessionProvider
}

func (p *liveTracingSessionProvider) GetSession(routerInfo router_info.RouterInfo) (netdb.I2NPSender, error) {
	session, err := p.inner.GetSession(routerInfo)
	if err != nil {
		return nil, err
	}
	targetHash, _ := routerInfo.IdentHash()
	return &liveTracingI2NPSender{t: p.t, inner: session, targetHash: targetHash}, nil
}

type liveTracingI2NPSender struct {
	t          *testing.T
	inner      netdb.I2NPSender
	targetHash common.Hash
}

func (s *liveTracingI2NPSender) QueueSendI2NP(msg i2np.Message) error {
	if dbStore, ok := msg.(*i2np.DatabaseStore); ok {
		s.t.Logf("publish trace dbstore: target=%s target_full=%s store_type=%d reply_token=%d reply_tunnel_id=%d reply_gateway=%s reply_gateway_full=%s key=%s key_full=%s",
			hashPrefix(s.targetHash),
			s.targetHash.String(),
			dbStore.StoreType,
			binary.BigEndian.Uint32(dbStore.ReplyToken[:]),
			binary.BigEndian.Uint32(dbStore.ReplyTunnelID[:]),
			hashPrefix(dbStore.ReplyGateway),
			dbStore.ReplyGateway.String(),
			hashPrefix(dbStore.Key),
			dbStore.Key.String(),
		)
	}
	return s.inner.QueueSendI2NP(msg)
}
