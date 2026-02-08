package bootstrap

import (
	"context"
	"encoding/hex"
	"math/rand"
	"sync"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/netdb/reseed"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ReseedResult holds the result from a single reseed server fetch operation.
type ReseedResult struct {
	// ServerURL is the URL of the reseed server
	ServerURL string
	// RouterInfos contains the successfully retrieved and validated RouterInfos
	RouterInfos []router_info.RouterInfo
	// Error contains any error that occurred during the fetch
	Error error
	// Duration is how long the fetch took
	Duration time.Duration
}

// MultiServerReseed fetches RouterInfos from multiple servers concurrently
// and applies the configured strategy to combine results.
// It requires at least MinReseedServers successful responses.
func (rb *ReseedBootstrap) MultiServerReseed(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	minServers := rb.config.MinReseedServers
	if minServers < 1 {
		minServers = 1
	}

	servers := rb.shuffleServers()

	log.WithFields(logger.Fields{
		"at":            "(ReseedBootstrap) MultiServerReseed",
		"phase":         "bootstrap",
		"reason":        "starting multi-server reseed",
		"min_servers":   minServers,
		"total_servers": len(servers),
		"strategy":      rb.config.ReseedStrategy,
	}).Info("starting multi-server reseed operation")

	results := rb.fetchFromServers(ctx, servers, minServers)
	successfulResults := filterSuccessful(results)

	if len(successfulResults) < minServers {
		log.WithFields(logger.Fields{
			"at":                 "(ReseedBootstrap) MultiServerReseed",
			"phase":              "bootstrap",
			"reason":             "insufficient successful reseed servers",
			"successful_servers": len(successfulResults),
			"min_required":       minServers,
			"total_attempted":    len(results),
		}).Error("multi-server reseed failed: insufficient servers responded")
		return nil, oops.Errorf("insufficient reseed servers: got %d, need %d",
			len(successfulResults), minServers)
	}

	combined := rb.applyStrategy(successfulResults)

	// Shuffle results for randomization
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(combined), func(i, j int) {
		combined[i], combined[j] = combined[j], combined[i]
	})

	// Limit results if requested
	if n > 0 && len(combined) > n {
		combined = combined[:n]
	}

	log.WithFields(logger.Fields{
		"at":                 "(ReseedBootstrap) MultiServerReseed",
		"phase":              "bootstrap",
		"reason":             "multi-server reseed completed",
		"successful_servers": len(successfulResults),
		"combined_routers":   len(combined),
		"strategy":           rb.config.ReseedStrategy,
	}).Info("multi-server reseed completed successfully")

	return combined, nil
}

// shuffleServers returns a randomized copy of configured servers
// to distribute load and avoid always hitting the same servers first.
func (rb *ReseedBootstrap) shuffleServers() []*config.ReseedConfig {
	servers := make([]*config.ReseedConfig, len(rb.config.ReseedServers))
	copy(servers, rb.config.ReseedServers)

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(servers), func(i, j int) {
		servers[i], servers[j] = servers[j], servers[i]
	})
	return servers
}

// fetchFromServers fetches from servers concurrently until minServers succeed or all fail.
// It uses a semaphore to limit concurrent requests.
func (rb *ReseedBootstrap) fetchFromServers(ctx context.Context, servers []*config.ReseedConfig, minServers int) []ReseedResult {
	var (
		results   []ReseedResult
		resultsMu sync.Mutex
		wg        sync.WaitGroup
		success   int
	)

	// Limit concurrent requests to avoid overwhelming the network
	const maxConcurrent = 3
	semaphore := make(chan struct{}, maxConcurrent)

	for _, server := range servers {
		// Check context cancellation
		select {
		case <-ctx.Done():
			log.WithFields(logger.Fields{
				"at":     "(ReseedBootstrap) fetchFromServers",
				"phase":  "bootstrap",
				"reason": "context cancelled during server iteration",
			}).Warn("stopping server iteration due to context cancellation")
			break
		default:
		}

		// Check if we have enough successful results
		resultsMu.Lock()
		if success >= minServers {
			resultsMu.Unlock()
			log.WithFields(logger.Fields{
				"at":      "(ReseedBootstrap) fetchFromServers",
				"phase":   "bootstrap",
				"reason":  "minimum servers reached",
				"success": success,
				"min":     minServers,
			}).Debug("stopping iteration: minimum successful servers reached")
			break
		}
		resultsMu.Unlock()

		wg.Add(1)
		go func(srv *config.ReseedConfig) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				resultsMu.Lock()
				results = append(results, ReseedResult{
					ServerURL: srv.Url,
					Error:     ctx.Err(),
				})
				resultsMu.Unlock()
				return
			}

			result := rb.fetchFromSingleServer(ctx, srv)

			resultsMu.Lock()
			results = append(results, result)
			if result.Error == nil && len(result.RouterInfos) > 0 {
				success++
			}
			resultsMu.Unlock()
		}(server)
	}

	wg.Wait()
	return results
}

// fetchFromSingleServer fetches RouterInfos from a single reseed server.
func (rb *ReseedBootstrap) fetchFromSingleServer(ctx context.Context, server *config.ReseedConfig) ReseedResult {
	startTime := time.Now()

	log.WithFields(logger.Fields{
		"at":         "(ReseedBootstrap) fetchFromSingleServer",
		"phase":      "bootstrap",
		"reason":     "fetching from server",
		"server_url": server.Url,
	}).Debug("starting fetch from reseed server")

	// Check context before making request
	if ctx.Err() != nil {
		return ReseedResult{
			ServerURL: server.Url,
			Error:     ctx.Err(),
			Duration:  time.Since(startTime),
		}
	}

	reseeder := reseed.NewReseed()
	routerInfos, err := reseeder.SingleReseed(server.Url)
	duration := time.Since(startTime)

	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":          "(ReseedBootstrap) fetchFromSingleServer",
			"phase":       "bootstrap",
			"reason":      "fetch failed",
			"server_url":  server.Url,
			"duration_ms": duration.Milliseconds(),
		}).Warn("reseed fetch failed")
		return ReseedResult{
			ServerURL: server.Url,
			Error:     err,
			Duration:  duration,
		}
	}

	// Validate and filter RouterInfos
	validRouterInfos := rb.validateAndFilterRouterInfos(routerInfos, server.Url)

	log.WithFields(logger.Fields{
		"at":            "(ReseedBootstrap) fetchFromSingleServer",
		"phase":         "bootstrap",
		"reason":        "fetch completed",
		"server_url":    server.Url,
		"duration_ms":   duration.Milliseconds(),
		"total_fetched": len(routerInfos),
		"valid_count":   len(validRouterInfos),
	}).Info("reseed fetch completed")

	return ReseedResult{
		ServerURL:   server.Url,
		RouterInfos: validRouterInfos,
		Duration:    duration,
	}
}

// applyStrategy combines RouterInfos according to the configured strategy.
func (rb *ReseedBootstrap) applyStrategy(results []ReseedResult) []router_info.RouterInfo {
	switch rb.config.ReseedStrategy {
	case config.ReseedStrategyIntersection:
		return rb.intersectionStrategy(results)
	case config.ReseedStrategyRandom:
		return rb.randomWeightedStrategy(results)
	default: // config.ReseedStrategyUnion
		return rb.unionStrategy(results)
	}
}

// unionStrategy returns all unique RouterInfos from any server.
// This provides the largest possible peer set.
func (rb *ReseedBootstrap) unionStrategy(results []ReseedResult) []router_info.RouterInfo {
	seen := make(map[string]router_info.RouterInfo)

	for _, r := range results {
		for _, ri := range r.RouterInfos {
			hash := routerInfoHash(ri)
			if _, exists := seen[hash]; !exists {
				seen[hash] = ri
			}
		}
	}

	combined := make([]router_info.RouterInfo, 0, len(seen))
	for _, ri := range seen {
		combined = append(combined, ri)
	}

	log.WithFields(logger.Fields{
		"at":             "(ReseedBootstrap) unionStrategy",
		"phase":          "bootstrap",
		"reason":         "union strategy applied",
		"server_count":   len(results),
		"unique_routers": len(combined),
	}).Debug("union strategy completed")

	return combined
}

// intersectionStrategy returns only RouterInfos present in ALL server responses.
// This provides stronger validation but may result in fewer peers.
func (rb *ReseedBootstrap) intersectionStrategy(results []ReseedResult) []router_info.RouterInfo {
	if len(results) == 0 {
		return nil
	}

	// Count appearances of each RouterInfo
	counts := make(map[string]int)
	riMap := make(map[string]router_info.RouterInfo)

	for _, r := range results {
		seen := make(map[string]bool) // Track seen in this server to avoid double-counting
		for _, ri := range r.RouterInfos {
			hash := routerInfoHash(ri)
			if !seen[hash] {
				counts[hash]++
				seen[hash] = true
				riMap[hash] = ri
			}
		}
	}

	// Only keep RouterInfos present in ALL responses
	var intersection []router_info.RouterInfo
	for hash, count := range counts {
		if count == len(results) {
			intersection = append(intersection, riMap[hash])
		}
	}

	log.WithFields(logger.Fields{
		"at":                   "(ReseedBootstrap) intersectionStrategy",
		"phase":                "bootstrap",
		"reason":               "intersection strategy applied",
		"server_count":         len(results),
		"intersection_routers": len(intersection),
	}).Debug("intersection strategy completed")

	return intersection
}

// randomWeightedStrategy randomly selects RouterInfos, weighted by how many servers returned each.
// RouterInfos returned by multiple servers are more likely to be selected.
func (rb *ReseedBootstrap) randomWeightedStrategy(results []ReseedResult) []router_info.RouterInfo {
	counts := make(map[string]int)
	riMap := make(map[string]router_info.RouterInfo)

	for _, r := range results {
		seen := make(map[string]bool)
		for _, ri := range r.RouterInfos {
			hash := routerInfoHash(ri)
			if !seen[hash] {
				counts[hash]++
				seen[hash] = true
				riMap[hash] = ri
			}
		}
	}

	// Build weighted selection (RIs from multiple servers appear multiple times)
	var weighted []router_info.RouterInfo
	for hash, count := range counts {
		ri := riMap[hash]
		for i := 0; i < count; i++ {
			weighted = append(weighted, ri)
		}
	}

	// Shuffle weighted list
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(weighted), func(i, j int) {
		weighted[i], weighted[j] = weighted[j], weighted[i]
	})

	// Deduplicate after shuffle (preserving weighted order)
	seen := make(map[string]bool)
	var result []router_info.RouterInfo
	for _, ri := range weighted {
		hash := routerInfoHash(ri)
		if !seen[hash] {
			result = append(result, ri)
			seen[hash] = true
		}
	}

	log.WithFields(logger.Fields{
		"at":             "(ReseedBootstrap) randomWeightedStrategy",
		"phase":          "bootstrap",
		"reason":         "random weighted strategy applied",
		"server_count":   len(results),
		"unique_routers": len(result),
	}).Debug("random weighted strategy completed")

	return result
}

// routerInfoHash generates a unique hash for a RouterInfo based on its identity.
// Unlike GetRouterHashString which truncates for logging, this returns the full hash
// for accurate deduplication in strategy functions.
func routerInfoHash(ri router_info.RouterInfo) string {
	hash, err := ri.IdentHash()
	if err != nil {
		// Fall back to empty string on error - this RouterInfo won't deduplicate properly
		// but the caller should have validated the RouterInfo already
		return ""
	}
	return hex.EncodeToString(hash[:])
}

// filterSuccessful returns only successful ReseedResults (no error and has RouterInfos).
func filterSuccessful(results []ReseedResult) []ReseedResult {
	var successful []ReseedResult
	for _, r := range results {
		if r.Error == nil && len(r.RouterInfos) > 0 {
			successful = append(successful, r)
		}
	}
	return successful
}
