package tunnel

import (
	"github.com/go-i2p/logger"
)

// autoFallbackConfig holds the configuration needed for auto-fallback checks.
type autoFallbackConfig struct {
	fn        func() bool
	hopCount  int
	isInbound bool
	isClient  bool
}

// checkAutoFallback switches this pool to reduced-hop tunnels when the
// registered callback confirms no public address is available.
//   - Inbound pool: falls back to 0-hop (we are our own IBGW/IBEP).
//   - Outbound pool: falls back to 1-hop (the single OBEP we dialled can reply
//     via the already-open session, bypassing the need for inbound reachability).
//
// It is a no-op for client pools (hop count is application-specified), if the
// hop-count is already at the fallback minimum, or if no callback was registered.
func (p *Pool) checkAutoFallback() {
	config := p.getAutoFallbackConfig()

	if p.shouldSkipAutoFallback(config) {
		return
	}

	p.performAutoFallback(config)
}

// getAutoFallbackConfig retrieves the configuration for auto-fallback checks.
func (p *Pool) getAutoFallbackConfig() autoFallbackConfig {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return autoFallbackConfig{
		fn:        p.autoFallbackFn,
		hopCount:  p.config.HopCount,
		isInbound: p.config.IsInbound,
		isClient:  p.config.IsClientPool,
	}
}

// shouldSkipAutoFallback determines if auto-fallback should be skipped.
func (p *Pool) shouldSkipAutoFallback(config autoFallbackConfig) bool {
	if config.isClient {
		return true // client tunnel hop counts are application-specified; never reduce them
	}
	if config.fn == nil {
		return true
	}
	if !config.fn() {
		return true // public address present — no fallback needed
	}
	return false
}

// performAutoFallback reduces hop count for inbound or outbound pools when needed.
func (p *Pool) performAutoFallback(config autoFallbackConfig) {
	if config.isInbound {
		p.fallbackInbound(config.hopCount)
	} else {
		p.fallbackOutbound(config.hopCount)
	}
}

// fallbackInbound reduces inbound pool to zero-hop tunnels if needed.
func (p *Pool) fallbackInbound(hopCount int) {
	if hopCount == 0 {
		return // already at minimum
	}
	if err := p.SetHopCount(0); err == nil {
		log.WithFields(logger.Fields{
			"at":     "Pool.checkAutoFallback",
			"reason": "consecutive inbound build timeouts with no public address",
		}).Info("auto-fallback: switched inbound exploratory pool to zero-hop tunnels")
	}
}

// fallbackOutbound reduces outbound pool to one-hop tunnels if needed.
func (p *Pool) fallbackOutbound(hopCount int) {
	if hopCount <= 1 {
		return // already at minimum
	}
	if err := p.SetHopCount(1); err == nil {
		log.WithFields(logger.Fields{
			"at":     "Pool.checkAutoFallback",
			"reason": "consecutive outbound build timeouts with no public address",
		}).Info("auto-fallback: switched outbound exploratory pool to one-hop tunnels")
	}
}

// TriggerAutoFallbackCheck immediately evaluates the auto-fallback condition
// against the registered callback (e.g. "do we have a public address?"). Unlike
// the counter-based paths (RecordInboundBuildTimeout / RecordOutboundBuildTimeout),
// this bypasses the threshold check and fires unconditionally. It is intended for
// use by the router's startup goroutine so that a firewalled router can switch to
// reduced hops after one build-timeout period rather than waiting for
// autoFallbackThreshold consecutive failures.
// No-op for client pools (their hop count is application-specified).
func (p *Pool) TriggerAutoFallbackCheck() {
	p.checkAutoFallback()
}
