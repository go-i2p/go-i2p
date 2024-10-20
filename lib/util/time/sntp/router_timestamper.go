package sntp

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

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

	lastFailed := true

	if rt.priorityServers != nil {
		for _, servers := range rt.priorityServers {
			lastFailed = !rt.queryTime(servers, shortTimeout, preferIPv6)
			if !lastFailed {
				break
			}
		}
	}

	if rt.priorityServers == nil || lastFailed {
		prefIPv6 := preferIPv6 && rt.secureRandBool(0.75)
		lastFailed = !rt.queryTime(rt.servers, defaultTimeout, prefIPv6)
	}

	rt.mutex.Lock()
	if !rt.initialized {
		rt.initialized = true
	}
	rt.mutex.Unlock()

	return lastFailed
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
	rt.wellSynced = false

	for i := 0; i < rt.concurringServers; i++ {
		server := servers[rand.Intn(len(servers))]
		options := ntp.QueryOptions{
			Timeout: timeout,
			//TTL:     5,
		}

		if preferIPv6 {
			server = fmt.Sprintf("[%s]:123", server)
		}

		response, err := rt.ntpClient.QueryWithOptions(server, options)
		if err != nil {
			fmt.Printf("NTP query failed: %v\n", err)
			return false
		}

		now := time.Now().Add(response.ClockOffset)
		delta := now.Sub(time.Now())
		found[i] = delta

		if i == 0 {
			if absDuration(delta) < maxVariance {
				if absDuration(delta) < 500*time.Millisecond {
					rt.wellSynced = true
				}
				break
			} else {
				expectedDelta = delta
			}
		} else {
			if absDuration(delta-expectedDelta) > maxVariance {
				// Variance too high, fail this attempt
				return false
			}
		}
	}

	rt.stampTime(time.Now().Add(found[0]))
	return true
}

func (rt *RouterTimestamper) stampTime(now time.Time) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	for _, listener := range rt.listeners {
		listener.SetNow(now, 0)
	}
}

func (rt *RouterTimestamper) updateConfig() {
	serverList := defaultServerList
	rt.servers = strings.Split(serverList, ",")
	for i, server := range rt.servers {
		rt.servers[i] = strings.TrimSpace(server)
	}

	if rt.queryFrequency < minQueryFrequency {
		rt.queryFrequency = minQueryFrequency
	}

	if rt.concurringServers < 1 {
		rt.concurringServers = 1
	} else if rt.concurringServers > 4 {
		rt.concurringServers = 4
	}

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
