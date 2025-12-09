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
	waitGroup         sync.WaitGroup
	ntpClient         NTPClient
	timeOffset        time.Duration // Store the current time offset from system time
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
	maxVariance           = 10 * time.Second
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
	}
	rt.updateConfig()
	return rt
}

func (rt *RouterTimestamper) Start() {
	if rt.disabled || rt.initialized {
		return
	}
	rt.isRunning = true
	rt.waitGroup.Add(1)
	go rt.run()
}

func (rt *RouterTimestamper) Stop() {
	if rt.isRunning {
		rt.isRunning = false
		close(rt.stopChan)
		rt.waitGroup.Wait()
	}
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
		if l == listener {
			rt.listeners = append(rt.listeners[:i], rt.listeners[i+1:]...)
			break
		}
	}
}

func (rt *RouterTimestamper) WaitForInitialization() {
	start := time.Now()
	for {
		rt.mutex.Lock()
		initialized := rt.initialized
		rt.mutex.Unlock()
		if initialized {
			return
		}
		if time.Since(start) > maxWaitInitialization {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (rt *RouterTimestamper) TimestampNow() {
	if rt.initialized && rt.isRunning && !rt.disabled {
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
	}
}

/*
	func (rt *RouterTimestamper) run() {
		defer rt.waitGroup.Done()
		lastFailed := false
		for rt.isRunning {
			rt.updateConfig()
			preferIPv6 := checkIPv6Connectivity()
			if !rt.disabled {
				if rt.priorityServers != nil {
					for _, servers := range rt.priorityServers {
						lastFailed = !rt.queryTime(servers, shortTimeout, preferIPv6)
						if !lastFailed {
							break
						}
					}
				}
				if rt.priorityServers == nil || lastFailed {
					prefIPv6 := preferIPv6 && !lastFailed && rand.Intn(4) != 0
					lastFailed = !rt.queryTime(rt.servers, defaultTimeout, prefIPv6)
				}
			}

			rt.mutex.Lock()
			if !rt.initialized {
				rt.initialized = true
			}
			rt.mutex.Unlock()

			var sleepTime time.Duration
			if lastFailed {
				rt.consecutiveFails++
				if rt.consecutiveFails >= maxConsecutiveFails {
					sleepTime = 30 * time.Minute
				} else {
					sleepTime = 30 * time.Second
				}
			} else {
				rt.consecutiveFails = 0
				randomDelay := time.Duration(rand.Int63n(int64(rt.queryFrequency / 2)))
				sleepTime = rt.queryFrequency + randomDelay
				if rt.wellSynced {
					sleepTime *= 3
				}
			}

			select {
			case <-time.After(sleepTime):
			case <-rt.stopChan:
				return
			}
		}
	}
*/
func (rt *RouterTimestamper) run() {
	defer rt.waitGroup.Done()
	for rt.isRunning {
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
	if lastFailed {
		rt.consecutiveFails++
		if rt.consecutiveFails >= maxConsecutiveFails {
			return 30 * time.Minute
		}
		return 30 * time.Second
	}

	rt.consecutiveFails = 0
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

/*
	func (rt *RouterTimestamper) runOnce() {
		lastFailed := false
		rt.updateConfig()
		preferIPv6 := checkIPv6Connectivity()
		if !rt.disabled {
			if rt.priorityServers != nil {
				for _, servers := range rt.priorityServers {
					lastFailed = !rt.queryTime(servers, shortTimeout, preferIPv6)
					if !lastFailed {
						break
					}
				}
			}
			if rt.priorityServers == nil || lastFailed {
				prefIPv6 := preferIPv6 && !lastFailed && rand.Intn(4) != 0
				lastFailed = !rt.queryTime(rt.servers, defaultTimeout, prefIPv6)
			}
		}

		rt.mutex.Lock()
		if !rt.initialized {
			rt.initialized = true
		}
		rt.mutex.Unlock()
	}
*/
func (rt *RouterTimestamper) runOnce() {
	rt.performTimeQuery()
}

func (rt *RouterTimestamper) queryTime(servers []string, timeout time.Duration, preferIPv6 bool) bool {
	found := make([]time.Duration, rt.concurringServers)
	var expectedDelta time.Duration

	rt.resetSyncStatus()

	for i := 0; i < rt.concurringServers; i++ {
		delta, err := rt.performSingleNTPQuery(servers, timeout, preferIPv6)
		if err != nil {
			return false
		}

		found[i] = delta

		if i == 0 {
			// Validate first sample and set sync status, but continue collecting
			// all concurrent samples for multi-server consensus
			rt.validateFirstSample(delta)
			expectedDelta = delta
		} else {
			if !rt.validateAdditionalSample(delta, expectedDelta) {
				return false
			}
		}
	}

	// Use median of all samples for robustness against outliers
	medianDelta := rt.calculateMedian(found)
	rt.stampTime(time.Now().Add(medianDelta))
	return true
}

// resetSyncStatus safely sets wellSynced to false with mutex protection.
func (rt *RouterTimestamper) resetSyncStatus() {
	rt.mutex.Lock()
	rt.wellSynced = false
	rt.mutex.Unlock()
}

// performSingleNTPQuery executes a single NTP query against a randomly selected server.
func (rt *RouterTimestamper) performSingleNTPQuery(servers []string, timeout time.Duration, preferIPv6 bool) (time.Duration, error) {
	server := rt.selectRandomServer(servers, preferIPv6)
	options := ntp.QueryOptions{
		Timeout: timeout,
		// TTL:     5,
	}

	response, err := rt.ntpClient.QueryWithOptions(server, options)
	if err != nil {
		log.WithError(err).WithField("server", server).Debug("NTP query failed")
		return 0, err
	}

	// Validate NTP response before using it to prevent accepting invalid/malicious time sources
	if !rt.validateResponse(response) {
		log.WithField("server", server).Debug("NTP response failed validation")
		return 0, fmt.Errorf("NTP response validation failed for server %s", server)
	}

	now := time.Now().Add(response.ClockOffset)
	delta := time.Until(now)
	return delta, nil
}

// selectRandomServer chooses a random server from the list.
// The preferIPv6 parameter is currently unused but retained for future implementation
// of IPv6-specific server selection logic. The beevik/ntp library handles DNS resolution
// and will use IPv6 or IPv4 based on system configuration.
func (rt *RouterTimestamper) selectRandomServer(servers []string, preferIPv6 bool) string {
	server := servers[rand.Intn(len(servers))]
	return server
}

// validateFirstSample checks if the first time sample is within acceptable variance.
func (rt *RouterTimestamper) validateFirstSample(delta time.Duration) bool {
	if absDuration(delta) < maxVariance {
		if absDuration(delta) < 500*time.Millisecond {
			rt.setSyncedStatus(true)
		}
		return true
	}
	return false
}

// validateAdditionalSample checks if subsequent samples are consistent with the expected delta.
func (rt *RouterTimestamper) validateAdditionalSample(delta, expectedDelta time.Duration) bool {
	return absDuration(delta-expectedDelta) <= maxVariance
}

// calculateMedian computes the median of a slice of time.Duration values.
// For robustness, the median is preferred over the mean as it's less affected by outliers.
func (rt *RouterTimestamper) calculateMedian(deltas []time.Duration) time.Duration {
	if len(deltas) == 0 {
		return 0
	}
	if len(deltas) == 1 {
		return deltas[0]
	}

	// Create a copy to avoid modifying the original slice
	sorted := make([]time.Duration, len(deltas))
	copy(sorted, deltas)

	// Simple insertion sort for small arrays (typically 3 servers)
	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}

	// Return the middle value (or average of two middle values for even length)
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

// setSyncedStatus safely sets wellSynced status with mutex protection.
func (rt *RouterTimestamper) setSyncedStatus(synced bool) {
	rt.mutex.Lock()
	rt.wellSynced = synced
	rt.mutex.Unlock()
}

// stampTime stores the time offset and notifies listeners.
// Per NTCP2 specification, timestamps are rounded to the nearest second
// to prevent clock bias accumulation in the I2P network.
func (rt *RouterTimestamper) stampTime(now time.Time) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	// Round to nearest second per NTCP2 spec for RouterInfo timestamps
	roundedNow := now.Round(time.Second)

	// Store the time offset for GetCurrentTime
	rt.timeOffset = time.Until(roundedNow)

	for _, listener := range rt.listeners {
		listener.SetNow(roundedNow, 0)
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

func getLocalCountryCode() string {
	return ""
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
