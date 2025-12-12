package i2pcontrol

import (
	"context"
	"encoding/json"
	"fmt"
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
		return nil, NewRPCErrorWithData(ErrCodeInvalidParams, "invalid Echo parameter", err.Error())
	}

	return map[string]interface{}{
		"Result": req.Echo,
	}, nil
}

// GetRateHandler implements the GetRate RPC method.
// Returns bandwidth statistics from the router.
//
// Request params:
//
//	{
//	  "i2p.router.net.bw.inbound.15s": null,
//	  "i2p.router.net.bw.outbound.15s": null
//	}
//
// Response:
//
//	{
//	  "i2p.router.net.bw.inbound.15s": 12345.67,
//	  "i2p.router.net.bw.outbound.15s": 23456.78
//	}
//
// The request specifies which statistics are desired.
// Any field with a null value will be populated in the response.
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
// Returns bandwidth statistics for requested fields.
func (h *GetRateHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	// Parse request to see which fields are requested
	var req map[string]interface{}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, NewRPCErrorWithData(ErrCodeInvalidParams, "invalid GetRate parameters", err.Error())
	}

	// Get current bandwidth stats
	bwStats := h.stats.GetBandwidthStats()

	// Build response with requested fields
	result := make(map[string]interface{})

	// Check which fields were requested (any field present in req)
	if _, ok := req["i2p.router.net.bw.inbound.15s"]; ok {
		result["i2p.router.net.bw.inbound.15s"] = bwStats.InboundRate
	}
	if _, ok := req["i2p.router.net.bw.outbound.15s"]; ok {
		result["i2p.router.net.bw.outbound.15s"] = bwStats.OutboundRate
	}

	// If no specific fields requested, return all
	if len(result) == 0 {
		result["i2p.router.net.bw.inbound.15s"] = bwStats.InboundRate
		result["i2p.router.net.bw.outbound.15s"] = bwStats.OutboundRate
	}

	return result, nil
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
func (h *RouterInfoHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	// Parse request to see which fields are requested
	var req map[string]interface{}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, NewRPCErrorWithData(ErrCodeInvalidParams, "invalid RouterInfo parameters", err.Error())
	}

	// Get current router stats
	routerStats := h.stats.GetRouterInfo()

	// Get bandwidth stats
	bandwidthStats := h.stats.GetBandwidthStats()

	// Build response with requested fields
	result := make(map[string]interface{})

	// Map of available fields to their values
	availableFields := map[string]interface{}{
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

	// If specific fields requested, return only those
	if len(req) > 0 {
		for field := range req {
			if value, exists := availableFields[field]; exists {
				result[field] = value
			}
		}
	}

	// If no specific fields or none matched, return common fields
	if len(result) == 0 {
		result["i2p.router.uptime"] = routerStats.Uptime
		result["i2p.router.version"] = routerStats.Version
		result["i2p.router.net.tunnels.participating"] = routerStats.ParticipatingTunnels
		result["i2p.router.netdb.knownpeers"] = routerStats.KnownPeers
		result["i2p.router.net.status"] = getStatusCode(h.stats.IsRunning())
	}

	return result, nil
}

// getStatusCode converts running status to I2PControl status code.
// Status codes:
//   - 0: OK (running normally)
//   - 1: Testing
//   - 2: Firewalled
//   - 3: Hidden
//   - 4: Warning
//   - 5: Error
func getStatusCode(running bool) int {
	if running {
		return 0 // OK
	}
	return 5 // Error (not running)
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
// Note: Restart is not implemented initially.
// Shutdown will stop the router gracefully.
type RouterManagerHandler struct {
	// RouterControl provides control operations
	RouterControl interface {
		// Stop initiates graceful router shutdown
		Stop()
	}
}

// NewRouterManagerHandler creates a new RouterManager handler.
//
// Parameters:
//   - control: Router control interface (typically the Router itself)
func NewRouterManagerHandler(control interface{ Stop() }) *RouterManagerHandler {
	return &RouterManagerHandler{
		RouterControl: control,
	}
}

// Handle processes the RouterManager request.
// Executes requested control operations.
func (h *RouterManagerHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	// Parse request to see which operations are requested
	var req map[string]interface{}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, NewRPCErrorWithData(ErrCodeInvalidParams, "invalid RouterManager parameters", err.Error())
	}

	result := make(map[string]interface{})

	// Handle Shutdown request
	if _, ok := req["Shutdown"]; ok {
		// Initiate shutdown in background (don't block RPC response)
		go func() {
			log.Info("Shutdown requested via I2PControl")
			h.RouterControl.Stop()
		}()
		result["Shutdown"] = nil
	}

	// Handle Restart request
	if _, ok := req["Restart"]; ok {
		// Restart not yet implemented
		return nil, NewRPCErrorWithData(ErrCodeNotImpl, "Restart not implemented", "use Shutdown and manually restart")
	}

	// Handle Reseed request
	if _, ok := req["Reseed"]; ok {
		// Reseed not yet implemented
		return nil, NewRPCErrorWithData(ErrCodeNotImpl, "Reseed not implemented", "automatic reseed occurs on startup")
	}

	// If no operations requested, return error
	if len(result) == 0 {
		return nil, NewRPCErrorWithData(ErrCodeInvalidParams, "no operations specified", "specify at least one operation")
	}

	return result, nil
}

// NetworkSettingHandler implements the NetworkSetting RPC method.
// Provides read-only access to router configuration.
//
// Request params:
//
//	{
//	  "i2p.router.net.ntcp.port": null,
//	  "i2p.router.net.ntcp.hostname": null
//	}
//
// Response:
//
//	{
//	  "i2p.router.net.ntcp.port": 12345,
//	  "i2p.router.net.ntcp.hostname": "localhost"
//	}
//
// Note: Only read operations are supported initially.
// Write operations (changing config) will be added later.
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
func (h *NetworkSettingHandler) buildAvailableSettings(netConfig NetworkConfig) map[string]interface{} {
	return map[string]interface{}{
		"i2p.router.net.ntcp.port":     netConfig.NTCP2Port,
		"i2p.router.net.ntcp.hostname": netConfig.NTCP2Hostname,
		"i2p.router.net.ntcp.autoip":   true,  // Default behavior
		"i2p.router.upnp.enabled":      false, // Not yet implemented
		"i2p.router.bandwidth.in":      netConfig.BandwidthLimitIn,
		"i2p.router.bandwidth.out":     netConfig.BandwidthLimitOut,
	}
}

// processRequestedSettings processes a map of requested settings and returns their values.
// Returns an error if a write operation is attempted (non-null value provided).
func (h *NetworkSettingHandler) processRequestedSettings(req, availableSettings map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for setting := range req {
		if value, exists := availableSettings[setting]; exists {
			// Check if this is a write operation (non-null value)
			if req[setting] != nil {
				return nil, NewRPCErrorWithData(ErrCodeNotImpl, "setting modification not implemented", fmt.Sprintf("cannot modify %s", setting))
			}
			result[setting] = value
		} else {
			// Unknown setting - return null to indicate not available
			result[setting] = nil
		}
	}

	return result, nil
}

// buildDefaultSettings returns a map containing the most commonly requested network settings.
func (h *NetworkSettingHandler) buildDefaultSettings(netConfig NetworkConfig) map[string]interface{} {
	return map[string]interface{}{
		"i2p.router.net.ntcp.port":     netConfig.NTCP2Port,
		"i2p.router.net.ntcp.hostname": netConfig.NTCP2Hostname,
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
}

// NewI2PControlHandler creates a new I2PControl handler.
//
// Parameters:
//   - authManager: Authentication manager for password changes
func NewI2PControlHandler(authManager interface{ ChangePassword(string) int }) *I2PControlHandler {
	return &I2PControlHandler{
		authManager: authManager,
	}
}

// Handle processes the I2PControl request.
// Handles password changes and returns SettingsSaved status.
func (h *I2PControlHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req map[string]interface{}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, NewRPCErrorWithData(ErrCodeInvalidParams, "invalid I2PControl parameters", err.Error())
	}

	result := make(map[string]interface{})
	settingsSaved := false

	if err := handlePasswordChange(h.authManager, req, result, &settingsSaved); err != nil {
		return nil, err
	}

	if err := validateNotImplementedSettings(req); err != nil {
		return nil, err
	}

	return buildResultWithSettingsSaved(result, settingsSaved)
}

// handlePasswordChange processes password change requests from the I2PControl API.
// Updates the result map and settingsSaved flag if password is successfully changed.
func handlePasswordChange(authManager interface{ ChangePassword(string) int }, req map[string]interface{}, result map[string]interface{}, settingsSaved *bool) error {
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

	log.WithFields(map[string]interface{}{
		"at":      "handlePasswordChange",
		"revoked": revokedCount,
	}).Info("password changed via RPC")

	result["i2pcontrol.password"] = nil
	*settingsSaved = true

	return nil
}

// validateNotImplementedSettings checks for settings that are not yet implemented.
// Returns an error if port or address change is requested.
func validateNotImplementedSettings(req map[string]interface{}) error {
	if _, ok := req["i2pcontrol.port"]; ok {
		return NewRPCErrorWithData(ErrCodeNotImpl, "port change not implemented", "requires server restart")
	}

	if _, ok := req["i2pcontrol.address"]; ok {
		return NewRPCErrorWithData(ErrCodeNotImpl, "address change not implemented", "requires server restart")
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
