package i2pcontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/logger"
	"github.com/spf13/viper"
)

// EchoHandler implements the Echo RPC method.
// Simply returns whatever value is sent in the "Echo" parameter.
// This is useful for testing RPC connectivity.
//
// Request params:
//
//	{
//	  "Echo": "any_value"
//	}
//
// Response:
//
//	{
//	  "Echo": "any_value"
//	}
type EchoHandler struct{}

// NewEchoHandler creates a new Echo handler.
func NewEchoHandler() *EchoHandler {
	return &EchoHandler{}
}

// Handle processes the Echo request.
// Extracts the "Echo" parameter and returns it unchanged.
// Note: Java I2P returns {"Result": value} not {"Echo": value}
func (h *EchoHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req struct {
		Echo interface{} `json:"Echo"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		log.WithField("reason", err.Error()).Debug("i2pcontrol: Echo params unmarshal failed")
		return nil, NewRPCError(ErrCodeInvalidParams, "malformed Echo parameters")
	}

	return map[string]interface{}{
		"Result": req.Echo,
	}, nil
}

// GetRateHandler implements the GetRate RPC method.
// Supports two calling conventions:
//
// 1. Java I2P spec style (used by go-i2pcontrol / go-i2p TUI):
//
//	{"Stat": "bw.sendBps", "Period": 300000}
//	→ {"Result": 12345.0}
//
// 2. Legacy field-list style:
//
//	{"i2p.router.net.bw.inbound.15s": null, "i2p.router.net.bw.outbound.15s": null}
//	→ {"i2p.router.net.bw.inbound.15s": 12345.67, ...}
//
// The Stat/Period style MUST return {"Result": float64} or clients like
// go-i2pcontrol will panic when they type-assert retpre["Result"].(float64).
type GetRateHandler struct {
	stats RouterStatsProvider
}

// NewGetRateHandler creates a new GetRate handler.
//
// Parameters:
//   - stats: Statistics provider for bandwidth data
func NewGetRateHandler(stats RouterStatsProvider) *GetRateHandler {
	return &GetRateHandler{
		stats: stats,
	}
}

// Handle processes the GetRate request.
// Detects Stat/Period format first; falls back to legacy field-list format.
func (h *GetRateHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req map[string]interface{}
	if err := json.Unmarshal(params, &req); err != nil {
		log.WithField("reason", err.Error()).Debug("i2pcontrol: GetRate params unmarshal failed")
		return nil, NewRPCError(ErrCodeInvalidParams, "malformed GetRate parameters")
	}

	// Java I2P spec: {"Stat": "statName", "Period": ms} → {"Result": float64}
	// go-i2pcontrol and the i2ptui TUI use this format. Without it the client
	// does retpre["Result"].(float64) on a nil map value and panics.
	if statName, ok := req["Stat"]; ok {
		var periodMs int64 = 60000 // default 60s
		if raw, ok := req["Period"]; ok {
			if v, ok := raw.(float64); ok {
				periodMs = int64(v)
			}
		}
		val := h.resolveStatName(statName, periodMs)
		log.WithFields(map[string]interface{}{
			"stat":   statName,
			"period": periodMs,
			"result": val,
		}).Debug("i2pcontrol: GetRate Stat/Period style")
		return map[string]interface{}{"Result": val}, nil
	}

	// Legacy field-list style: {"i2p.router.net.bw.inbound.15s": null, ...}
	bwStats := h.stats.GetBandwidthStats()
	result := make(map[string]interface{})

	if _, ok := req["i2p.router.net.bw.inbound.15s"]; ok {
		result["i2p.router.net.bw.inbound.15s"] = bwStats.InboundRate
	}
	if _, ok := req["i2p.router.net.bw.outbound.15s"]; ok {
		result["i2p.router.net.bw.outbound.15s"] = bwStats.OutboundRate
	}

	// Return all fields when none were explicitly requested.
	if len(result) == 0 {
		result["i2p.router.net.bw.inbound.15s"] = bwStats.InboundRate
		result["i2p.router.net.bw.outbound.15s"] = bwStats.OutboundRate
	}

	return result, nil
}

// resolveStatName maps a Java I2P stat name to a float64 value for the given
// period window (in milliseconds). Delegates to GetRateForPeriod so that all
// stat/period logic lives in one place.
func (h *GetRateHandler) resolveStatName(statName interface{}, periodMs int64) float64 {
	name, ok := statName.(string)
	if !ok {
		return 0
	}
	return h.stats.GetRateForPeriod(name, periodMs)
}

// RouterInfoHandler implements the RouterInfo RPC method.
// Returns general router status and statistics.
//
// Request params:
//
//	{
//	  "i2p.router.uptime": null,
//	  "i2p.router.version": null,
//	  "i2p.router.net.tunnels.participating": null,
//	  "i2p.router.netdb.knownpeers": null
//	}
//
// Response:
//
//	{
//	  "i2p.router.uptime": 3600000,
//	  "i2p.router.version": "0.1.0-go",
//	  "i2p.router.net.tunnels.participating": 10,
//	  "i2p.router.netdb.knownpeers": 150,
//	  "i2p.router.net.tunnels.inbound": 5,
//	  "i2p.router.net.tunnels.outbound": 5
//	}
//
// The request specifies which statistics are desired.
// Any field with a null value will be populated in the response.
type RouterInfoHandler struct {
	stats RouterStatsProvider
}

// NewRouterInfoHandler creates a new RouterInfo handler.
//
// Parameters:
//   - stats: Statistics provider for router information
func NewRouterInfoHandler(stats RouterStatsProvider) *RouterInfoHandler {
	return &RouterInfoHandler{
		stats: stats,
	}
}

// Handle processes the RouterInfo request.
// Returns router statistics for requested fields.
// buildAvailableFields constructs a map of all available RouterInfo fields and their current values.
func (h *RouterInfoHandler) buildAvailableFields() map[string]interface{} {
	routerStats := h.stats.GetRouterInfo()
	bandwidthStats := h.stats.GetBandwidthStats()

	return map[string]interface{}{
		"i2p.router.uptime":                    routerStats.Uptime,
		"i2p.router.version":                   routerStats.Version,
		"i2p.router.status":                    routerStats.Status,
		"i2p.router.net.tunnels.participating": routerStats.ParticipatingTunnels,
		"i2p.router.netdb.knownpeers":          routerStats.KnownPeers,
		"i2p.router.netdb.activepeers":         routerStats.ActivePeersCount,
		"i2p.router.netdb.fastpeers":           routerStats.FastPeersCount,
		"i2p.router.netdb.highcapacitypeers":   routerStats.HighCapacityPeersCount,
		"i2p.router.netdb.isreseeding":         routerStats.IsReseeding,
		"i2p.router.net.tunnels.inbound":       routerStats.InboundTunnels,
		"i2p.router.net.tunnels.outbound":      routerStats.OutboundTunnels,
		"i2p.router.net.status":                getStatusCode(h.stats.IsRunning()),
		"i2p.router.net.bw.inbound.1s":         bandwidthStats.InboundRate,
		"i2p.router.net.bw.inbound.15s":        bandwidthStats.InboundRate,
		"i2p.router.net.bw.outbound.1s":        bandwidthStats.OutboundRate,
		"i2p.router.net.bw.outbound.15s":       bandwidthStats.OutboundRate,
	}
}

// selectRequestedOrDefaultFields returns the requested fields from available fields,
// or a set of default fields if no specific fields were requested or none matched.
func selectRequestedOrDefaultFields(req, availableFields map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	if len(req) > 0 {
		for field := range req {
			if value, exists := availableFields[field]; exists {
				result[field] = value
			}
		}
	}

	if len(result) == 0 {
		result["i2p.router.uptime"] = availableFields["i2p.router.uptime"]
		result["i2p.router.version"] = availableFields["i2p.router.version"]
		result["i2p.router.net.tunnels.participating"] = availableFields["i2p.router.net.tunnels.participating"]
		result["i2p.router.netdb.knownpeers"] = availableFields["i2p.router.netdb.knownpeers"]
		result["i2p.router.net.status"] = availableFields["i2p.router.net.status"]
	}

	return result
}

// Handle processes an I2PControl RouterInfo RPC request, returning the requested or default router information fields.
func (h *RouterInfoHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req map[string]interface{}
	if err := json.Unmarshal(params, &req); err != nil {
		log.WithField("reason", err.Error()).Debug("i2pcontrol: RouterInfo params unmarshal failed")
		return nil, NewRPCError(ErrCodeInvalidParams, "malformed RouterInfo parameters")
	}

	availableFields := h.buildAvailableFields()
	result := selectRequestedOrDefaultFields(req, availableFields)

	return result, nil
}

// getStatusCode converts running status to I2PControl status code.
// Status codes defined by the I2PControl spec:
//   - 0:  OK (running normally)
//   - 1:  TESTING
//   - 2:  FIREWALLED
//   - 3:  HIDDEN
//   - 4:  WARN_FIREWALLED_AND_FAST
//   - 5:  WARN_FIREWALLED_AND_FLOODFILL
//   - 6:  WARN_FIREWALLED_WITH_INBOUND_TCP
//   - 7:  WARN_FIREWALLED_WITH_UDP_DISABLED
//   - 8:  ERROR_I2CP
//   - 9:  ERROR_CLOCK_SKEW
//   - 10: ERROR_PRIVATE_TCP_ADDRESS
//   - 11: ERROR_SYMMETRIC_NAT
//   - 12: ERROR_UDP_PORT_IN_USE
//   - 13: ERROR_NO_ACTIVE_PEERS_CHECK_CONNECTION_AND_FIREWALL
//   - 14: ERROR_UDP_DISABLED_AND_TCP_UNSET
//
// Deprecated: Use RouterStatsProvider.GetNetworkStatus() and networkStatusString() directly.
func getStatusCode(running bool) int {
	if running {
		return 0 // OK
	}
	return 8 // ERROR_I2CP — generic connection/IPC error when router is not running
}

// networkStatusString maps an I2PControl numeric status code to the human-readable
// status name used in the i2p.router.status RouterInfo field.
func networkStatusString(code int) string {
	switch code {
	case 0:
		return "OK"
	case 1:
		return "TESTING"
	case 2:
		return "FIREWALLED"
	case 3:
		return "HIDDEN"
	case 4:
		return "WARN_FIREWALLED_AND_FAST"
	case 5:
		return "WARN_FIREWALLED_AND_FLOODFILL"
	case 6:
		return "WARN_FIREWALLED_WITH_INBOUND_TCP"
	case 7:
		return "WARN_FIREWALLED_WITH_UDP_DISABLED"
	case 8:
		return "ERROR_I2CP"
	case 9:
		return "ERROR_CLOCK_SKEW"
	case 10:
		return "ERROR_PRIVATE_TCP_ADDRESS"
	case 11:
		return "ERROR_SYMMETRIC_NAT"
	case 12:
		return "ERROR_UDP_PORT_IN_USE"
	case 13:
		return "ERROR_NO_ACTIVE_PEERS_CHECK_CONNECTION_AND_FIREWALL"
	case 14:
		return "ERROR_UDP_DISABLED_AND_TCP_UNSET"
	default:
		return "UNKNOWN"
	}
}

// RouterManagerHandler implements the RouterManager RPC method.
// Provides router control operations (shutdown, restart, reseed).
//
// Request params:
//
//	{
//	  "Shutdown": null,
//	  "Reseed": null
//	}
//
// Response:
//
//	{
//	  "Shutdown": null,
//	  "Reseed": null
//	}
//
// Note: Restart performs a stop; the process supervisor is expected to restart the process.
// Shutdown will stop the router gracefully.
type RouterManagerHandler struct {
	// RouterControl provides control operations
	RouterControl interface {
		// Stop initiates graceful router shutdown
		Stop()
		// Reseed triggers a manual NetDB reseed operation
		Reseed() error
	}
	// ctx is the server context used to signal cancellation to handler goroutines.
	ctx context.Context
	// wg tracks handler goroutines so the server can wait for them on shutdown.
	wg *sync.WaitGroup
}

// NewRouterManagerHandler creates a new RouterManager handler.
//
// Parameters:
//   - ctx: server context for cancellation propagation to handler goroutines
//   - wg: WaitGroup to track handler goroutines for clean shutdown
//   - control: Router control interface (typically the Router itself)
func NewRouterManagerHandler(ctx context.Context, wg *sync.WaitGroup, control interface {
	Stop()
	Reseed() error
},
) *RouterManagerHandler {
	return &RouterManagerHandler{
		RouterControl: control,
		ctx:           ctx,
		wg:            wg,
	}
}

// Handle processes the RouterManager request.
// Executes requested control operations.
func (h *RouterManagerHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req map[string]interface{}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, NewRPCErrorWithData(ErrCodeInvalidParams, "invalid RouterManager parameters", err.Error())
	}

	result := make(map[string]interface{})
	h.handleShutdown(req, result)
	h.handleShutdownGraceful(req, result)
	h.handleRestart(req, result)
	h.handleRestartGraceful(req, result)
	h.handleReseed(req, result)
	h.handleFindUpdates(req, result)
	h.handleUpdate(req, result)

	if len(result) == 0 {
		return nil, NewRPCErrorWithData(ErrCodeInvalidParams, "no operations specified", "specify at least one operation")
	}

	return result, nil
}

// handleShutdown initiates a graceful router shutdown if requested.
// The shutdown runs asynchronously — the response confirms the request was accepted,
// not that shutdown completed. The client connection may be closed before Stop() finishes.
func (h *RouterManagerHandler) handleShutdown(req, result map[string]interface{}) {
	if _, ok := req["Shutdown"]; ok {
		if h.RouterControl == nil {
			log.WithFields(logger.Fields{"at": "handleShutdown"}).Warn("Shutdown requested but RouterControl is nil")
			result["Shutdown"] = "error: router control not available"
			return
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			log.WithFields(logger.Fields{"at": "handleShutdown"}).Info("Shutdown requested via I2PControl")
			h.RouterControl.Stop()
			log.WithFields(logger.Fields{"at": "handleShutdown"}).Info("Router shutdown completed via I2PControl")
		}()
		result["Shutdown"] = nil
	}
}

// handleRestart performs a graceful shutdown for supervisor-managed restart if requested.
// Like handleShutdown, the response confirms the request was accepted, not completion.
func (h *RouterManagerHandler) handleRestart(req, result map[string]interface{}) {
	if _, ok := req["Restart"]; ok {
		if h.RouterControl == nil {
			log.WithFields(logger.Fields{"at": "handleRestart"}).Warn("Restart requested but RouterControl is nil")
			result["Restart"] = "error: router control not available"
			return
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			log.WithFields(logger.Fields{"at": "handleRestart"}).Info("Restart requested via I2PControl (performing shutdown for supervisor restart)")
			h.RouterControl.Stop()
			log.WithFields(logger.Fields{"at": "handleRestart"}).Info("Router restart/stop completed via I2PControl")
		}()
		result["Restart"] = nil
	}
}

// handleReseed triggers a manual NetDB reseed operation if requested.
func (h *RouterManagerHandler) handleReseed(req, result map[string]interface{}) {
	if _, ok := req["Reseed"]; ok {
		if h.RouterControl == nil {
			log.WithFields(logger.Fields{"at": "handleReseed"}).Warn("Reseed requested but RouterControl is nil")
			result["Reseed"] = "error: router control not available"
			return
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			log.WithFields(logger.Fields{"at": "handleReseed"}).Info("Reseed requested via I2PControl")
			if err := h.RouterControl.Reseed(); err != nil {
				log.WithError(err).Error("Reseed via I2PControl failed")
			}
		}()
		result["Reseed"] = nil
	}
}

// handleShutdownGraceful is the spec-compliant alias for a graceful shutdown.
// Java I2P delays the shutdown by ~11 minutes; go-i2p delegates to the same
// Stop() path as immediate shutdown and relies on the process supervisor.
func (h *RouterManagerHandler) handleShutdownGraceful(req, result map[string]interface{}) {
	if _, ok := req["ShutdownGraceful"]; ok {
		if h.RouterControl == nil {
			log.WithFields(logger.Fields{"at": "handleShutdownGraceful"}).Warn("ShutdownGraceful requested but RouterControl is nil")
			result["ShutdownGraceful"] = "error: router control not available"
			return
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			log.WithFields(logger.Fields{"at": "handleShutdownGraceful"}).Info("ShutdownGraceful requested via I2PControl")
			h.RouterControl.Stop()
		}()
		result["ShutdownGraceful"] = nil
	}
}

// handleRestartGraceful is the spec-compliant alias for a graceful restart.
// Like handleShutdownGraceful, go-i2p performs a clean stop and relies on the
// external process supervisor to restart the process.
func (h *RouterManagerHandler) handleRestartGraceful(req, result map[string]interface{}) {
	if _, ok := req["RestartGraceful"]; ok {
		if h.RouterControl == nil {
			log.WithFields(logger.Fields{"at": "handleRestartGraceful"}).Warn("RestartGraceful requested but RouterControl is nil")
			result["RestartGraceful"] = "error: router control not available"
			return
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			log.WithFields(logger.Fields{"at": "handleRestartGraceful"}).Info("RestartGraceful requested via I2PControl (stop only; supervisor must restart)")
			h.RouterControl.Stop()
		}()
		result["RestartGraceful"] = nil
	}
}

// handleFindUpdates responds to the FindUpdates RouterManager operation.
// go-i2p does not have an auto-update mechanism, so this always returns false.
// Returning a valid bool prevents clients (go-i2pcontrol) from panicking on
// the type assertion retpre["FindUpdates"].(bool).
func (h *RouterManagerHandler) handleFindUpdates(req, result map[string]interface{}) {
	if _, ok := req["FindUpdates"]; ok {
		// No update mechanism in go-i2p; return false (no updates available).
		result["FindUpdates"] = false
	}
}

// handleUpdate responds to the Update RouterManager operation.
// go-i2p does not support in-process updates; the operation is acknowledged
// per the spec (null result) but no action is taken.
func (h *RouterManagerHandler) handleUpdate(req, result map[string]interface{}) {
	if _, ok := req["Update"]; ok {
		result["Update"] = nil
	}
}

// NetworkSettingHandler implements the NetworkSetting RPC method.
// Supports both reading and writing router network configuration.
//
// Writable settings (pass a non-null value to change):
//   - "i2p.router.net.ntcp.port"     → transport.ntcp2_port     (restart required)
//   - "i2p.router.net.ntcp.hostname" → transport.ntcp2_hostname  (restart required)
//   - "i2p.router.bandwidth.in"      → router.max_bandwidth      (live update)
//   - "i2p.router.bandwidth.out"     → router.max_bandwidth      (live update)
//
// Pass null as the value to read the current setting without changing it.
type NetworkSettingHandler struct {
	stats RouterStatsProvider
}

// NewNetworkSettingHandler creates a new NetworkSetting handler.
//
// Parameters:
//   - stats: Router statistics provider for accessing network configuration
func NewNetworkSettingHandler(stats RouterStatsProvider) *NetworkSettingHandler {
	return &NetworkSettingHandler{
		stats: stats,
	}
}

// Handle processes the NetworkSetting request.
// Returns requested configuration values.
// Handle processes a NetworkSetting request and returns the requested configuration values.
// Returns network settings from the router configuration, or an error if parsing fails.
func (h *NetworkSettingHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req map[string]interface{}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, NewRPCErrorWithData(ErrCodeInvalidParams, "invalid NetworkSetting parameters", err.Error())
	}

	netConfig := h.stats.GetNetworkConfig()
	availableSettings := h.buildAvailableSettings(netConfig)

	// If specific settings requested, return only those
	if len(req) > 0 {
		return h.processRequestedSettings(req, availableSettings)
	}

	// If no settings requested, return common settings
	return h.buildDefaultSettings(netConfig), nil
}

// buildAvailableSettings creates a map of all available network settings with their current values.
// Includes both the go-i2p native keys and the Java I2P spec aliases so that
// the go-i2pcontrol client library (and i2ptui) can read them without panicking.
func (h *NetworkSettingHandler) buildAvailableSettings(netConfig NetworkConfig) map[string]interface{} {
	return map[string]interface{}{
		// NTCP2 transport settings
		"i2p.router.net.ntcp.port":     netConfig.NTCP2Port,
		"i2p.router.net.ntcp.hostname": netConfig.NTCP2Hostname,
		"i2p.router.net.ntcp.autoip":   true,

		// SSU2 (UDP) transport settings
		"i2p.router.net.ssu2.port":     netConfig.SSU2Port,
		"i2p.router.net.ssu2.hostname": netConfig.SSU2Hostname,
		// Alias: some clients use "i2p.router.net.ssu.port" for SSU2
		"i2p.router.net.ssu.port": netConfig.SSU2Port,

		// Bandwidth limits — exposed under both the go-i2p key and the Java I2P
		// NetworkSetting spec key (i2p.router.net.bw.*). The TUI calls the
		// spec keys; returning them prevents the client from showing "N/A".
		"i2p.router.bandwidth.in":  netConfig.BandwidthLimitIn,
		"i2p.router.bandwidth.out": netConfig.BandwidthLimitOut,
		"i2p.router.net.bw.in":     netConfig.BandwidthLimitIn,
		"i2p.router.net.bw.out":    netConfig.BandwidthLimitOut,

		// Bandwidth share percentage (0–100).
		"i2p.router.net.bw.share": netConfig.SharePercentage,

		// UPnP — not yet implemented; returned as a readable bool
		"i2p.router.net.upnp":     viper.GetBool("router.upnp_enabled"),
		"i2p.router.upnp.enabled": viper.GetBool("router.upnp_enabled"),
	}
}

// processRequestedSettings processes a map of requested settings and returns their values.
// Read operations (null value) return the current setting value.
// Write operations (non-null value) persist the change via Viper and return the new value.
// Settings that require a restart are flagged with "RestartNeeded".
func (h *NetworkSettingHandler) processRequestedSettings(req, availableSettings map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for setting := range req {
		if _, exists := availableSettings[setting]; !exists {
			result[setting] = nil
			continue
		}
		if req[setting] == nil {
			result[setting] = availableSettings[setting]
			continue
		}
		if err := h.applySettingChange(setting, req[setting], result); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// settingViperKey maps an I2PControl setting name to its Viper config key.
// Returns empty string if the setting is not writable.
var settingViperKey = map[string]string{
	"i2p.router.net.ntcp.port":     "transport.ntcp2_port",
	"i2p.router.net.ntcp.hostname": "transport.ntcp2_hostname",
	"i2p.router.bandwidth.in":      "router.max_bandwidth_in",
	"i2p.router.bandwidth.out":     "router.max_bandwidth_out",
	"i2p.router.net.bw.in":         "router.max_bandwidth_in",
	"i2p.router.net.bw.out":        "router.max_bandwidth_out",
	"i2p.router.net.bw.share":      "router.share_percentage",
	"i2p.router.net.ssu2.port":     "transport.ssu2_port",
	"i2p.router.net.ssu.port":      "transport.ssu2_port",
	"i2p.router.net.upnp":          "router.upnp_enabled",
	"i2p.router.upnp.enabled":      "router.upnp_enabled",
}

// restartRequiredSettings is the set of settings whose changes require a router restart.
var restartRequiredSettings = map[string]bool{
	"i2p.router.net.ntcp.port":     true,
	"i2p.router.net.ntcp.hostname": true,
	"i2p.router.net.ssu2.port":     true,
	"i2p.router.net.ssu.port":      true,
}

// applySettingChange persists a single setting change via Viper.
// Returns an error if the setting is not writable or the value type is invalid.
func (h *NetworkSettingHandler) applySettingChange(setting string, value interface{}, result map[string]interface{}) error {
	viperKey, ok := settingViperKey[setting]
	if !ok {
		return NewRPCErrorWithData(ErrCodeNotImpl, "setting is read-only", fmt.Sprintf("cannot modify %s", setting))
	}

	normalized, err := normalizeSettingValue(setting, value)
	if err != nil {
		return NewRPCErrorWithData(ErrCodeInvalidParams, "invalid setting value", err.Error())
	}

	viper.Set(viperKey, normalized)
	if err := viper.WriteConfig(); err != nil {
		log.WithFields(map[string]interface{}{
			"at":      "applySettingChange",
			"setting": setting,
			"error":   err.Error(),
		}).Warn("setting changed in memory but failed to persist to config file")
	}

	result[setting] = normalized
	if restartRequiredSettings[setting] {
		result["RestartNeeded"] = true
	}
	result["SettingsSaved"] = true
	return nil
}

// normalizeSettingValue validates the type and range of a setting value before
// validatePortSetting coerces value to an integer and validates it as a valid
// TCP/UDP port number in the range [1, 65535].
func validatePortSetting(setting string, value interface{}) (interface{}, error) {
	port, err := coerceInt(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be an integer: %w", setting, err)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("%s must be in [1,65535], got %d", setting, port)
	}
	return port, nil
}

// validateHostnameSetting checks that value is a string containing a valid
// hostname.
func validateHostnameSetting(setting string, value interface{}) (interface{}, error) {
	host, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("%s must be a string, got %T", setting, value)
	}
	if err := validateHostname(host); err != nil {
		return nil, err
	}
	return host, nil
}

// validateBandwidthSetting coerces value to a non-negative integer bandwidth.
func validateBandwidthSetting(setting string, value interface{}) (interface{}, error) {
	bw, err := coerceInt(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be a non-negative integer: %w", setting, err)
	}
	if bw < 0 {
		return nil, fmt.Errorf("%s must be non-negative, got %d", setting, bw)
	}
	return bw, nil
}

// validateSharePercentage validates the bandwidth share percentage (0–100).
func validateSharePercentage(setting string, value interface{}) (interface{}, error) {
	v, err := coerceInt(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be an integer: %w", setting, err)
	}
	if v < 0 || v > 100 {
		return nil, fmt.Errorf("%s must be in [0,100], got %d", setting, v)
	}
	return v, nil
}

// validateBoolSetting coerces value to a boolean.
func validateBoolSetting(setting string, value interface{}) (interface{}, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		switch v {
		case "true", "1", "yes":
			return true, nil
		case "false", "0", "no":
			return false, nil
		}
		return nil, fmt.Errorf("%s must be a boolean, got %q", setting, v)
	case float64:
		return v != 0, nil
	default:
		return nil, fmt.Errorf("%s must be a boolean, got %T", setting, value)
	}
}

// it is written through viper. JSON numbers decode as float64; integers are
// rounded-trip validated to catch non-integer payloads ("3.5", "abc").
// Returns the canonical Go value (e.g. int for ports) on success.
func normalizeSettingValue(setting string, value interface{}) (interface{}, error) {
	switch setting {
	case "i2p.router.net.ntcp.port", "i2p.router.net.ssu2.port", "i2p.router.net.ssu.port":
		return validatePortSetting(setting, value)
	case "i2p.router.net.ntcp.hostname":
		return validateHostnameSetting(setting, value)
	case "i2p.router.bandwidth.in", "i2p.router.bandwidth.out",
		"i2p.router.net.bw.in", "i2p.router.net.bw.out":
		return validateBandwidthSetting(setting, value)
	case "i2p.router.net.bw.share":
		return validateSharePercentage(setting, value)
	case "i2p.router.net.upnp", "i2p.router.upnp.enabled":
		return validateBoolSetting(setting, value)
	default:
		// Future-proof: unknown keys fall through unchanged.
		return value, nil
	}
}

// coerceInt converts a JSON-decoded value into a Go int. JSON numbers decode
// as float64 by default; this helper rejects non-integer floats.
func coerceInt(value interface{}) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("value %v is not an integer", v)
		}
		return int(v), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, err
		}
		return int(n), nil
	default:
		return 0, fmt.Errorf("unsupported type %T", value)
	}
}

// validateHostname accepts IP literals, DNS hostnames, and the empty string
// (interpreted by the transport as "bind-all"). It rejects overly long inputs
// and characters that are invalid in DNS labels.
func validateHostname(host string) error {
	if host == "" {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("hostname exceeds 253 bytes")
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '.':
		default:
			return fmt.Errorf("hostname contains invalid character %q", r)
		}
	}
	return nil
}

// buildDefaultSettings returns a map containing the most commonly requested network settings.
// Includes the Java I2P spec keys (i2p.router.net.bw.*) alongside the go-i2p
// native keys so that the TUI and go-i2pcontrol library see populated values.
func (h *NetworkSettingHandler) buildDefaultSettings(netConfig NetworkConfig) map[string]interface{} {
	return map[string]interface{}{
		"i2p.router.net.ntcp.port":     netConfig.NTCP2Port,
		"i2p.router.net.ntcp.hostname": netConfig.NTCP2Hostname,
		"i2p.router.bandwidth.in":      netConfig.BandwidthLimitIn,
		"i2p.router.bandwidth.out":     netConfig.BandwidthLimitOut,
		"i2p.router.net.bw.in":         netConfig.BandwidthLimitIn,
		"i2p.router.net.bw.out":        netConfig.BandwidthLimitOut,
		"i2p.router.net.bw.share":      netConfig.SharePercentage,
		"i2p.router.net.ssu2.port":     netConfig.SSU2Port,
		"i2p.router.net.upnp":          viper.GetBool("router.upnp_enabled"),
	}
}

// I2PControlHandler implements the I2PControl RPC method.
// Manages I2PControl server settings (password, port, address).
//
// Request params:
//
//	{
//	  "i2pcontrol.password": "new_password"
//	}
//
// Response:
//
//	{
//	  "i2pcontrol.password": null,
//	  "SettingsSaved": true
//	}
//
// Note: Only password changes are implemented initially.
// Port and address changes would require server restart and are deferred.
type I2PControlHandler struct {
	authManager interface {
		// ChangePassword updates password and revokes all tokens
		ChangePassword(newPassword string) int
	}
	// config holds a reference to the I2PControl configuration so that
	// password changes are persisted to the config struct (not just in-memory auth state).
	config *config.I2PControlConfig
}

// NewI2PControlHandler creates a new I2PControl handler.
//
// Parameters:
//   - authManager: Authentication manager for password changes
//   - cfg: I2PControl config for persisting password changes
func NewI2PControlHandler(authManager interface{ ChangePassword(string) int }, cfg *config.I2PControlConfig) *I2PControlHandler {
	return &I2PControlHandler{
		authManager: authManager,
		config:      cfg,
	}
}

// Handle processes the I2PControl request.
// Handles password, port, and address changes. Port and address changes are
// persisted but require a restart to take effect.
func (h *I2PControlHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req map[string]interface{}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, NewRPCErrorWithData(ErrCodeInvalidParams, "invalid I2PControl parameters", err.Error())
	}

	result := make(map[string]interface{})
	settingsSaved := false

	if err := handlePasswordChange(h.authManager, h.config, req, result, &settingsSaved); err != nil {
		return nil, err
	}

	// Persist port/address changes (restart required)
	if val, ok := req["i2pcontrol.port"]; ok && val != nil {
		settingsSaved = true
		result["RestartNeeded"] = true
		result["i2pcontrol.port"] = val
	}
	if val, ok := req["i2pcontrol.address"]; ok && val != nil {
		settingsSaved = true
		result["RestartNeeded"] = true
		result["i2pcontrol.address"] = val
	}

	if err := validateNotImplementedSettings(req); err != nil {
		return nil, err
	}

	return buildResultWithSettingsSaved(result, settingsSaved)
}

// handlePasswordChange processes password change requests from the I2PControl API.
// Updates the auth manager, persists the new password to the config struct,
// and sets the settingsSaved flag on success.
func handlePasswordChange(authManager interface{ ChangePassword(string) int }, cfg *config.I2PControlConfig, req, result map[string]interface{}, settingsSaved *bool) error {
	newPassword, ok := req["i2pcontrol.password"]
	if !ok || newPassword == nil {
		return nil
	}

	passwordStr, ok := newPassword.(string)
	if !ok {
		return NewRPCErrorWithData(ErrCodeInvalidParams, "password must be a string", fmt.Sprintf("got %T", newPassword))
	}

	if passwordStr == "" {
		return NewRPCError(ErrCodeInvalidParams, "password cannot be empty")
	}

	revokedCount := authManager.ChangePassword(passwordStr)

	// Persist password change to both the in-memory config struct and to disk
	// via viper so the new password survives router restarts.
	if cfg != nil {
		cfg.Password = passwordStr
	}
	viper.Set("i2pcontrol.password", passwordStr)
	if err := viper.WriteConfig(); err != nil {
		// Non-fatal: the in-memory password is already updated for this session.
		// Log a warning so the operator knows the change won't survive a restart.
		log.WithFields(map[string]interface{}{
			"at":    "handlePasswordChange",
			"error": err.Error(),
		}).Warn("password changed in memory but failed to persist to config file")
	}

	log.WithFields(map[string]interface{}{
		"at":      "handlePasswordChange",
		"revoked": revokedCount,
	}).Info("password changed via RPC")

	result["i2pcontrol.password"] = nil
	*settingsSaved = true

	return nil
}

// validateNotImplementedSettings checks for settings that are not yet implemented.
// Port and address changes are persisted but require a server restart to take effect.
func validateNotImplementedSettings(req map[string]interface{}) error {
	if val, ok := req["i2pcontrol.port"]; ok && val != nil {
		viper.Set("i2pcontrol.port", val)
		if err := viper.WriteConfig(); err != nil {
			log.WithFields(map[string]interface{}{
				"at":    "validateNotImplementedSettings",
				"error": err.Error(),
			}).Warn("i2pcontrol.port changed in memory but failed to persist")
		}
		// Port change is persisted but requires restart to take effect
	}

	if val, ok := req["i2pcontrol.address"]; ok && val != nil {
		viper.Set("i2pcontrol.address", val)
		if err := viper.WriteConfig(); err != nil {
			log.WithFields(map[string]interface{}{
				"at":    "validateNotImplementedSettings",
				"error": err.Error(),
			}).Warn("i2pcontrol.address changed in memory but failed to persist")
		}
		// Address change is persisted but requires restart to take effect
	}

	return nil
}

// buildResultWithSettingsSaved finalizes the result map with the SettingsSaved flag.
// Returns an error if no settings were specified in the request.
func buildResultWithSettingsSaved(result map[string]interface{}, settingsSaved bool) (interface{}, error) {
	if len(result) == 0 {
		return nil, NewRPCErrorWithData(ErrCodeInvalidParams, "no settings specified", "specify at least one setting to change")
	}

	result["SettingsSaved"] = settingsSaved
	return result, nil
}
