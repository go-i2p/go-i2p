package sntp

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-i2p/crypto/rand"

	"github.com/beevik/ntp"
)

type NTPClient interface {
	QueryWithOptions(host string, options ntp.QueryOptions) (*ntp.Response, error)
}

type DefaultNTPClient struct{}

func (c *DefaultNTPClient) QueryWithOptions(host string, options ntp.QueryOptions) (*ntp.Response, error) {
	return ntp.QueryWithOptions(host, options)
}

// ntpSample holds the result of a single NTP query, including both the
// clock offset (delta) and the server's stratum level for quality assessment.
type ntpSample struct {
	delta   time.Duration
	stratum uint8
}

type RouterTimestamper struct {
	servers           []string
	priorityServers   [][]string
	listeners         []UpdateListener
	queryFrequency    time.Duration
	concurringServers int
	consecutiveFails  int
	disabled          bool
	initialized       bool
	wellSynced        bool
	isRunning         bool
	mutex             sync.Mutex
	zones             *Zones
	stopChan          chan struct{}
	stopOnce          sync.Once
	waitGroup         sync.WaitGroup
	ntpClient         NTPClient
	timeOffset        time.Duration // Store the current time offset from system time
	// initChan is closed exactly once when initialization completes.
	// WaitForInitialization blocks on this channel instead of busy-polling.
	initChan chan struct{}
}

const (
	minQueryFrequency     = 5 * time.Minute
	defaultQueryFrequency = 11 * time.Minute
	defaultServerList     = "0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org"
	defaultDisabled       = false
	defaultConcurring     = 3
	maxConsecutiveFails   = 10
	defaultTimeout        = 10 * time.Second
	shortTimeout          = 5 * time.Second
	maxWaitInitialization = 45 * time.Second
	maxVariance           = 10 * time.Second // Max inter-sample variance for NTP consistency checks
)

func NewRouterTimestamper(client NTPClient) *RouterTimestamper {
	rt := &RouterTimestamper{
		listeners:         []UpdateListener{},
		disabled:          defaultDisabled,
		queryFrequency:    defaultQueryFrequency,
		concurringServers: defaultConcurring,
		zones:             NewZones(),
		stopChan:          make(chan struct{}),
		ntpClient:         client,
		initChan:          make(chan struct{}),
	}
	rt.updateConfig()
	return rt
}

func (rt *RouterTimestamper) Start() {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	if rt.disabled || rt.initialized {
		return
	}
	rt.isRunning = true
	rt.waitGroup.Add(1)
	go rt.run()
}

func (rt *RouterTimestamper) Stop() {
	rt.mutex.Lock()
	if !rt.isRunning {
		rt.mutex.Unlock()
		return
	}
	rt.isRunning = false
	rt.mutex.Unlock()
	rt.stopOnce.Do(func() {
		close(rt.stopChan)
	})
	rt.waitGroup.Wait()
}

func (rt *RouterTimestamper) AddListener(listener UpdateListener) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	rt.listeners = append(rt.listeners, listener)
}

func (rt *RouterTimestamper) RemoveListener(listener UpdateListener) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	for i, l := range rt.listeners {
		if listenersMatch(l, listener) {
			rt.listeners = append(rt.listeners[:i], rt.listeners[i+1:]...)
			break
		}
	}
}

// listenersMatch compares two listeners for identity. If both implement
// ListenerIdentifier, their IDs are compared. Otherwise, pointer equality is used.
func listenersMatch(a, b UpdateListener) bool {
	aidObj, aOk := a.(ListenerIdentifier)
	bidObj, bOk := b.(ListenerIdentifier)
	if aOk && bOk {
		return aidObj.ListenerID() == bidObj.ListenerID()
	}
	return a == b
}

func (rt *RouterTimestamper) WaitForInitialization() {
	select {
	case <-rt.initChan:
		// Initialization completed
	case <-time.After(maxWaitInitialization):
		// Timeout expired
	}
}

func (rt *RouterTimestamper) TimestampNow() {
	rt.mutex.Lock()
	canRun := rt.initialized && rt.isRunning && !rt.disabled
	rt.mutex.Unlock()
	if canRun {
		go rt.runOnce()
	}
}

func (rt *RouterTimestamper) secureRandBool(probability float64) bool {
	return rand.Float64() < probability
}

func (rt *RouterTimestamper) performTimeQuery() bool {
	rt.updateConfig()
	preferIPv6 := checkIPv6Connectivity()

	if rt.disabled {
		return false
	}

	priorityServers, servers := rt.getServerLists()
	lastFailed := rt.tryPriorityServers(priorityServers, preferIPv6)

	if len(priorityServers) == 0 || lastFailed {
		lastFailed = rt.tryDefaultServers(servers, preferIPv6)
	}

	rt.markInitialized()
	return lastFailed
}

func (rt *RouterTimestamper) getServerLists() ([][]string, []string) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	return rt.priorityServers, rt.servers
}

func (rt *RouterTimestamper) tryPriorityServers(priorityServers [][]string, preferIPv6 bool) bool {
	for _, serverList := range priorityServers {
		if rt.queryTime(serverList, shortTimeout, preferIPv6) {
			return false
		}
	}
	return true
}

func (rt *RouterTimestamper) tryDefaultServers(servers []string, preferIPv6 bool) bool {
	prefIPv6 := preferIPv6 && rt.secureRandBool(0.75)
	return !rt.queryTime(servers, defaultTimeout, prefIPv6)
}

func (rt *RouterTimestamper) markInitialized() {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	if !rt.initialized {
		rt.initialized = true
		// Close initChan to unblock all goroutines waiting in WaitForInitialization.
		// Safe to close exactly once since we check !rt.initialized under the mutex.
		close(rt.initChan)
	}
}

func (rt *RouterTimestamper) run() {
	defer rt.waitGroup.Done()
	for {
		rt.mutex.Lock()
		running := rt.isRunning
		rt.mutex.Unlock()
		if !running {
			return
		}
		lastFailed := rt.performTimeQuery()
		sleepTime := rt.calculateSleepDuration(lastFailed)

		if !rt.waitWithCancellation(sleepTime) {
			return
		}
	}
}

// calculateSleepDuration determines the appropriate sleep duration based on query results.
// It adjusts the sleep time based on consecutive failures and synchronization status.
func (rt *RouterTimestamper) calculateSleepDuration(lastFailed bool) time.Duration {
	rt.mutex.Lock()
	if lastFailed {
		rt.consecutiveFails++
		fails := rt.consecutiveFails
		if fails >= maxConsecutiveFails {
			rt.mutex.Unlock()
			rt.notifySyncLost()
			return 30 * time.Minute
		}
		rt.mutex.Unlock()
		rt.notifySyncFailure(fails)
		return 30 * time.Second
	}

	rt.consecutiveFails = 0
	rt.mutex.Unlock()

	randomDelay := time.Duration(rand.Int63n(int64(rt.queryFrequency / 2)))
	sleepTime := rt.queryFrequency + randomDelay

	rt.mutex.Lock()
	wellSynced := rt.wellSynced
	rt.mutex.Unlock()

	if wellSynced {
		sleepTime *= 3
	}

	return sleepTime
}

// notifySyncFailure notifies ExtendedUpdateListener implementations of a sync failure.
func (rt *RouterTimestamper) notifySyncFailure(consecutiveFails int) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	for _, listener := range rt.listeners {
		if ext, ok := listener.(ExtendedUpdateListener); ok {
			ext.OnSyncFailure(consecutiveFails)
		}
	}
}

// notifySyncLost notifies ExtendedUpdateListener implementations that sync was lost.
func (rt *RouterTimestamper) notifySyncLost() {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	for _, listener := range rt.listeners {
		if ext, ok := listener.(ExtendedUpdateListener); ok {
			ext.OnSyncLost()
		}
	}
}

// waitWithCancellation waits for the specified duration or until cancellation is requested.
// Returns true if the wait completed normally, false if cancelled.
func (rt *RouterTimestamper) waitWithCancellation(duration time.Duration) bool {
	select {
	case <-time.After(duration):
		return true
	case <-rt.stopChan:
		return false
	}
}

func (rt *RouterTimestamper) runOnce() {
	rt.performTimeQuery()
}

func (rt *RouterTimestamper) queryTime(servers []string, timeout time.Duration, preferIPv6 bool) bool {
	samples := make([]ntpSample, 0, rt.concurringServers)
	rt.resetSyncStatus()

	for i := 0; i < rt.concurringServers; i++ {
		sample, ok := rt.queryWithRetry(servers, timeout, preferIPv6)
		if !ok {
			return false
		}

		if i == 0 {
			rt.checkSyncStatus(sample.delta)
		} else if !rt.validateAdditionalSample(sample.delta, samples[0].delta) {
			return false
		}
		samples = append(samples, sample)
	}

	median := rt.selectMedianSample(samples)
	rt.stampTime(time.Now().Add(median.delta), median.stratum)
	rt.notifyListenersOnSuccess()
	return true
}

// resetSyncStatus safely sets wellSynced to false with mutex protection.
func (rt *RouterTimestamper) resetSyncStatus() {
	rt.mutex.Lock()
	rt.wellSynced = false
	rt.mutex.Unlock()
}

// queryWithRetry attempts to query NTP servers, excluding previously failed
// servers from retries to avoid wasting timeout cycles on known-bad servers.
func (rt *RouterTimestamper) queryWithRetry(servers []string, timeout time.Duration, preferIPv6 bool) (ntpSample, bool) {
	tried := make(map[string]bool)
	for attempt := 0; attempt < len(servers); attempt++ {
		server := rt.selectRandomServerExcluding(servers, preferIPv6, tried)
		if server == "" {
			return ntpSample{}, false
		}
		tried[server] = true
		sample, err := rt.querySingleServer(server, timeout)
		if err == nil {
			return sample, true
		}
	}
	return ntpSample{}, false
}

// querySingleServer executes a single NTP query against a specific server
// and returns the clock offset and stratum directly from the NTP response.
func (rt *RouterTimestamper) querySingleServer(server string, timeout time.Duration) (ntpSample, error) {
	if server == "" {
		return ntpSample{}, fmt.Errorf("no NTP server specified")
	}
	options := ntp.QueryOptions{
		Timeout: timeout,
	}

	response, err := rt.ntpClient.QueryWithOptions(server, options)
	if err != nil {
		log.WithError(err).WithField("server", server).Debug("NTP query failed")
		return ntpSample{}, err
	}

	if !rt.validateResponse(response) {
		log.WithField("server", server).Debug("NTP response failed validation")
		return ntpSample{}, fmt.Errorf("NTP response validation failed for server %s", server)
	}

	// Use response.ClockOffset directly as the delta — this is already the
	// computed clock offset from the NTP exchange. Avoids jitter from
	// double time.Now() calls.
	return ntpSample{delta: response.ClockOffset, stratum: response.Stratum}, nil
}

// selectRandomServer chooses a random server from the list.
// Wraps selectRandomServerExcluding with no exclusions.
func (rt *RouterTimestamper) selectRandomServer(servers []string, preferIPv6 bool) string {
	return rt.selectRandomServerExcluding(servers, preferIPv6, nil)
}

// selectRandomServerExcluding chooses a random server, excluding already-tried
// servers and preferring IPv6-reachable servers when requested.
func (rt *RouterTimestamper) selectRandomServerExcluding(servers []string, preferIPv6 bool, exclude map[string]bool) string {
	candidates := make([]string, 0, len(servers))
	for _, s := range servers {
		if !exclude[s] {
			candidates = append(candidates, s)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	if preferIPv6 {
		ipv6 := filterByAddressFamily(candidates, true)
		if len(ipv6) > 0 {
			candidates = ipv6
		}
	}
	return candidates[rand.Intn(len(candidates))]
}

// filterByAddressFamily filters servers by whether they resolve to IPv6 or IPv4
// addresses via DNS lookup. Returns servers matching the requested address family.
func filterByAddressFamily(servers []string, wantIPv6 bool) []string {
	var result []string
	for _, server := range servers {
		addrs, err := net.LookupHost(server)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip == nil {
				continue
			}
			isIPv6 := ip.To4() == nil
			if isIPv6 == wantIPv6 {
				result = append(result, server)
				break
			}
		}
	}
	return result
}

// checkSyncStatus marks the timestamper as well-synced if the offset is small.
// Unlike the previous validateFirstSample, this never rejects the sample —
// the purpose of SNTP is to correct arbitrary clock drift.
func (rt *RouterTimestamper) checkSyncStatus(delta time.Duration) {
	if absDuration(delta) < 500*time.Millisecond {
		rt.setSyncedStatus(true)
	}
}

// validateAdditionalSample checks if subsequent samples are consistent with the expected delta.
func (rt *RouterTimestamper) validateAdditionalSample(delta, expectedDelta time.Duration) bool {
	return absDuration(delta-expectedDelta) <= maxVariance
}

// selectMedianSample returns the median sample from a slice of NTP samples,
// sorted by delta. The median is preferred over the mean for robustness
// against outliers. Returns the full sample (including stratum) of the median.
func (rt *RouterTimestamper) selectMedianSample(samples []ntpSample) ntpSample {
	if len(samples) == 0 {
		return ntpSample{}
	}
	if len(samples) == 1 {
		return samples[0]
	}

	sorted := make([]ntpSample, len(samples))
	copy(sorted, samples)

	// Simple insertion sort for small arrays (typically 3 servers)
	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j].delta > key.delta {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}

	return sorted[len(sorted)/2]
}

// setSyncedStatus safely sets wellSynced status with mutex protection.
func (rt *RouterTimestamper) setSyncedStatus(synced bool) {
	rt.mutex.Lock()
	rt.wellSynced = synced
	rt.mutex.Unlock()
}

// stampTime stores the time offset and notifies listeners with the actual
// NTP stratum value from the server response.
// Per NTCP2 specification, timestamps are rounded to the nearest second
// to prevent clock bias accumulation in the I2P network.
func (rt *RouterTimestamper) stampTime(now time.Time, stratum uint8) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	// Round to nearest second per NTCP2 spec for RouterInfo timestamps
	roundedNow := now.Round(time.Second)

	// Store the time offset for GetCurrentTime
	rt.timeOffset = time.Until(roundedNow)

	for _, listener := range rt.listeners {
		listener.SetNow(roundedNow, stratum)
	}
}

// notifyListenersOnSuccess notifies ExtendedUpdateListener implementations
// that synchronization succeeded.
func (rt *RouterTimestamper) notifyListenersOnSuccess() {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	if !rt.initialized {
		return
	}
	for _, listener := range rt.listeners {
		if ext, ok := listener.(ExtendedUpdateListener); ok {
			ext.OnInitialized()
		}
	}
}

// updateConfig refreshes RouterTimestamper configuration with current settings.
func (rt *RouterTimestamper) updateConfig() {
	// Protect configuration updates with mutex to prevent race conditions
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	rt.parseServerList()
	rt.validateConfigBounds()
	rt.setupPriorityServers()
}

// parseServerList splits and trims the default server list into individual server addresses.
func (rt *RouterTimestamper) parseServerList() {
	serverList := defaultServerList
	rt.servers = strings.Split(serverList, ",")
	for i, server := range rt.servers {
		rt.servers[i] = strings.TrimSpace(server)
	}
}

// validateConfigBounds ensures query frequency and concurrent server count are within acceptable ranges.
func (rt *RouterTimestamper) validateConfigBounds() {
	if rt.queryFrequency < minQueryFrequency {
		rt.queryFrequency = minQueryFrequency
	}

	if rt.concurringServers < 1 {
		rt.concurringServers = 1
	} else if rt.concurringServers > 4 {
		rt.concurringServers = 4
	}
}

// setupPriorityServers configures country and zone-based NTP server priorities.
func (rt *RouterTimestamper) setupPriorityServers() {
	country := getLocalCountryCode()
	if country != "" && country != "a1" && country != "a2" {
		rt.priorityServers = [][]string{}
		p1 := []string{
			fmt.Sprintf("0.%s.pool.ntp.org", country),
			fmt.Sprintf("1.%s.pool.ntp.org", country),
			fmt.Sprintf("2.%s.pool.ntp.org", country),
		}
		rt.priorityServers = append(rt.priorityServers, p1)
		zone := rt.zones.GetZone(country)
		if zone != "" {
			p2 := []string{
				fmt.Sprintf("0.%s.pool.ntp.org", zone),
				fmt.Sprintf("1.%s.pool.ntp.org", zone),
				fmt.Sprintf("2.%s.pool.ntp.org", zone),
			}
			rt.priorityServers = append(rt.priorityServers, p2)
		}
	} else {
		rt.priorityServers = nil
	}
}

func checkIPv6Connectivity() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To16() != nil && ipNet.IP.To4() == nil {
				return true
			}
		}
	}
	return false
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// getLocalCountryCode detects the router's country using the system timezone.
// This is privacy-safe: it uses only local system configuration (timezone files,
// environment variables) and makes no network calls. Returns a lowercase ISO
// 3166-1 alpha-2 country code (e.g. "us", "de") or "" if detection fails.
func getLocalCountryCode() string {
	tzName := detectIANATimezone()
	if tzName == "" {
		log.Debug("Could not detect IANA timezone for NTP geo-selection")
		return ""
	}

	cc := lookupCountryByTimezone(tzName)
	if cc == "" {
		log.WithField("timezone", tzName).Debug("No country code mapping for timezone")
		return ""
	}

	log.WithFields(map[string]interface{}{
		"timezone": tzName,
		"country":  cc,
	}).Debug("Detected country code for NTP geo-selection")
	return cc
}

// GetCurrentTime returns the current time adjusted by the stored NTP offset.
// This is a non-blocking operation that uses the most recent time offset
// from background NTP synchronization. It does not trigger new NTP queries.
func (rt *RouterTimestamper) GetCurrentTime() time.Time {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	// Return system time adjusted by the stored time offset
	return time.Now().Add(rt.timeOffset)
}

// GetServers returns a copy of the current server list safely
func (rt *RouterTimestamper) GetServers() []string {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	servers := make([]string, len(rt.servers))
	copy(servers, rt.servers)
	return servers
}

// GetPriorityServers returns a copy of the current priority server lists safely
func (rt *RouterTimestamper) GetPriorityServers() [][]string {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	if rt.priorityServers == nil {
		return nil
	}

	priorityServers := make([][]string, len(rt.priorityServers))
	for i, serverList := range rt.priorityServers {
		priorityServers[i] = make([]string, len(serverList))
		copy(priorityServers[i], serverList)
	}
	return priorityServers
}
