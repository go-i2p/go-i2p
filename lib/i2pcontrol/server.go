package i2pcontrol

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/nat"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Server provides an HTTP/HTTPS endpoint for I2PControl JSON-RPC requests.
// It integrates authentication, method dispatch, and graceful shutdown.
type Server struct {
	config      *config.I2PControlConfig
	authManager *AuthManager
	registry    *MethodRegistry
	stats       RouterStatsProvider
	httpServer  *http.Server
	listener    net.Listener // Listener for exposing actual bound address
	mu          sync.RWMutex // Protects listener field
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	stopOnce    sync.Once
}

// NewServer creates a new I2PControl server with the given configuration and statistics provider.
// It initializes authentication, registers all RPC method handlers, and prepares the HTTP server.
func NewServer(cfg *config.I2PControlConfig, stats RouterStatsProvider) (*Server, error) {
	if err := validateServerConfig(cfg, stats); err != nil {
		return nil, err
	}

	authManager, err := initializeAuthManager(cfg.Password)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	server := &Server{
		config:      cfg,
		authManager: authManager,
		stats:       stats,
		ctx:         ctx,
		cancel:      cancel,
	}

	server.registry = registerRPCHandlers(ctx, &server.wg, stats, authManager, cfg)
	server.httpServer = createHTTPServer(cfg, server)
	return server, nil
}

// validateServerConfig checks that required server configuration parameters are valid.
// Returns an error if config is nil, stats is nil, or password is empty.
// It additionally refuses to start when (a) StrictAuth is set and the password
// is the well-known default, or (b) the bind address resolves to a non-loopback
// interface while the insecure defaults (default password or plaintext HTTP)
// are in effect and no explicit opt-in has been granted.
func validateServerConfig(cfg *config.I2PControlConfig, stats RouterStatsProvider) error {
	if cfg == nil {
		return oops.Errorf("i2pcontrol: config cannot be nil")
	}
	if stats == nil {
		return oops.Errorf("i2pcontrol: stats provider cannot be nil")
	}
	if cfg.Password == "" {
		return oops.Errorf("i2pcontrol: password cannot be empty")
	}
	if cfg.StrictAuth && cfg.Password == defaultI2PControlPassword {
		return oops.Errorf("i2pcontrol: strict_auth is enabled and password is the default; set a non-default password")
	}
	return validateBindPolicy(cfg)
}

// defaultI2PControlPassword is the well-known upstream default that the
// backward-compatibility exception is scoped to.
const defaultI2PControlPassword = "itoopie"

// validateBindPolicy enforces the loopback-scoped permissive defaults.
// Non-loopback binds must either use HTTPS, set a non-default password, or
// explicitly opt into plaintext via AllowPlaintextNonLoopback.
func validateBindPolicy(cfg *config.I2PControlConfig) error {
	loopback, err := isLoopbackBind(cfg.Address)
	if err != nil {
		// An unparseable address is treated as the permissive default path
		// (e.g. Unix-socket style "unix:/path"); deeper validation happens
		// when ListenAndServe actually tries to bind.
		return nil
	}
	if loopback {
		return nil
	}
	if !cfg.UseHTTPS && !cfg.AllowPlaintextNonLoopback {
		return oops.Errorf("i2pcontrol: non-loopback bind %q requires use_https=true or allow_plaintext_non_loopback=true", cfg.Address)
	}
	if cfg.Password == defaultI2PControlPassword {
		return oops.Errorf("i2pcontrol: non-loopback bind %q refuses the default password; set a non-default password", cfg.Address)
	}
	return nil
}

// isLoopbackBind reports whether the host portion of addr resolves exclusively
// to loopback addresses. An empty host or a wildcard bind (0.0.0.0, ::) is
// treated as non-loopback. Consolidation for H-10: delegates to nat.IsLoopbackAddress.
func isLoopbackBind(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, err
	}
	// Delegate to shared nat.IsLoopbackAddress for hostname resolution and IP parsing
	return nat.IsLoopbackAddress(host), nil
}

// initializeAuthManager creates and initializes the authentication manager with the given password.
// Returns the auth manager or an error if initialization fails.
func initializeAuthManager(password string) (*AuthManager, error) {
	authManager, err := NewAuthManager(password)
	if err != nil {
		return nil, oops.Wrapf(err, "i2pcontrol: failed to create auth manager")
	}
	return authManager, nil
}

// registerRPCHandlers creates a method registry and registers all RPC handlers.
// Returns the configured registry with Echo, GetRate, RouterInfo, Authenticate,
// RouterManager, NetworkSetting, ClientServicesInfo, and I2PControl handlers.
func registerRPCHandlers(ctx context.Context, wg *sync.WaitGroup, stats RouterStatsProvider, authManager *AuthManager, cfg *config.I2PControlConfig) *MethodRegistry {
	registry := NewMethodRegistry()

	registry.Register("Echo", NewEchoHandler())
	registry.Register("GetRate", NewGetRateHandler(stats))
	registry.Register("RouterInfo", NewRouterInfoHandler(stats))
	registry.Register("Authenticate", newAuthenticateHandler(authManager, cfg))
	registry.Register("RouterManager", NewRouterManagerHandler(ctx, wg, stats.GetRouterControl()))
	registry.Register("NetworkSetting", NewNetworkSettingHandler(stats))
	registry.Register("ClientServicesInfo", NewClientServicesInfoHandler())
	registry.Register("I2PControl", NewI2PControlHandler(authManager, cfg))
	registry.Register("AdvancedSettings", NewAdvancedSettingsHandler())

	return registry
}

// newAuthenticateHandler creates an RPC handler for the Authenticate method.
func newAuthenticateHandler(authManager *AuthManager, cfg *config.I2PControlConfig) RPCHandlerFunc {
	return func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		req, err := parseAuthenticateRequest(params)
		if err != nil {
			return nil, err
		}

		if err := validateAuthenticateAPIVersion(req.API); err != nil {
			return nil, err
		}

		token, err := performAuthentication(authManager, req.Password, cfg)
		if err != nil {
			return nil, err
		}

		return buildAuthenticateResponse(req.API, token, req.Password), nil
	}
}

// parseAuthenticateRequest unmarshals the Authenticate RPC parameters.
func parseAuthenticateRequest(params json.RawMessage) (*struct {
	API      *int   `json:"API"`
	Password string `json:"Password"`
}, error,
) {
	var req struct {
		API      *int   `json:"API"`
		Password string `json:"Password"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		log.WithField("reason", err.Error()).Debug("i2pcontrol: Authenticate params unmarshal failed")
		return nil, NewRPCError(ErrCodeInvalidParams, "malformed Authenticate parameters")
	}

	return &req, nil
}

// validateAuthenticateAPIVersion checks if the API version is supported.
func validateAuthenticateAPIVersion(api *int) error {
	if api == nil {
		return NewRPCError(ErrCodeAPIVersionNotSpecified, "API version not specified")
	}
	if *api != 1 {
		return NewRPCError(ErrCodeAPIVersionNotSupported, fmt.Sprintf("API version %d is not supported", *api))
	}
	return nil
}

// performAuthentication attempts to authenticate with the password and generate a token.
func performAuthentication(authManager *AuthManager, password string, cfg *config.I2PControlConfig) (string, error) {
	token, err := authManager.Authenticate(password, cfg.TokenExpiration)
	if err != nil {
		if errors.Is(err, errTokenEntropyFailure) {
			log.WithField("reason", err.Error()).Error("i2pcontrol: failed to generate authentication token")
			return "", NewRPCError(ErrCodeInternalError, "authentication temporarily unavailable")
		}
		return "", NewRPCError(ErrCodeAuthFailed, err.Error())
	}
	return token, nil
}

// buildAuthenticateResponse constructs the Authenticate RPC response.
func buildAuthenticateResponse(api *int, token, password string) map[string]interface{} {
	resp := map[string]interface{}{
		"API":   *api,
		"Token": token,
	}
	if password == defaultI2PControlPassword {
		resp["Warning"] = "authenticated with the default password 'itoopie'; this is retained only for backward-compatibility and is not recommended for production"
		logDefaultPasswordAuth()
	}
	return resp
}

// createHTTPServer creates and configures the HTTP server with timeouts and RPC handlers.
// Returns the configured HTTP server ready to start.
func createHTTPServer(cfg *config.I2PControlConfig, server *Server) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/jsonrpc", server.handleRPC)
	mux.HandleFunc("/", server.handleRPC)

	return &http.Server{
		Addr:         cfg.Address,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Start begins listening for HTTP/HTTPS requests on the configured address.
// It returns immediately after starting the server in a goroutine.
func (s *Server) Start() error {
	if !s.config.Enabled {
		log.WithFields(logger.Fields{"at": "Start"}).Info("I2PControl server is disabled")
		return nil
	}
	return s.startEnabledServer()
}

// startEnabledServer starts listener serving and token cleanup for an enabled server.
func (s *Server) startEnabledServer() error {
	if err := s.startHTTPServer(); err != nil {
		return err
	}
	s.startTokenCleanup()

	return nil
}

// Addr returns the network address the server is listening on.
// Returns nil if the server has not started or listener is not initialized.
// This is useful for tests that use ephemeral ports (e.g., "127.0.0.1:0").
func (s *Server) Addr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// startHTTPServer validates startup prerequisites, binds the listening socket,
// and then launches the serving loop in a background goroutine.
func (s *Server) startHTTPServer() error {
	listener, err := s.createListener()
	if err != nil {
		return err
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		err := s.serveOnListener(listener)

		if err != nil && err != http.ErrServerClosed {
			log.WithFields(logger.Fields{
				"at":     "(Server).startHTTPServer",
				"reason": err.Error(),
			}).Error("I2PControl server error")
		}
	}()

	return nil
}

// createListener validates transport configuration and binds the listener.
func (s *Server) createListener() (net.Listener, error) {
	protocol := "HTTP"
	if s.config.UseHTTPS {
		protocol = "HTTPS"
	}

	log.WithFields(logger.Fields{
		"at":       "(Server).createListener",
		"address":  s.config.Address,
		"protocol": protocol,
	}).Info("Starting I2PControl server")

	if err := s.validateHTTPSConfig(); err != nil {
		return nil, err
	}

	// Note: net.Listen("tcp", addr) may attempt IPv6 resolution first if addr
	// is a hostname like "localhost". On systems with IPv6 disabled, this can
	// result in a confusing "bind: cannot assign requested address" error.
	// If you encounter this, specify an explicit IP literal instead:
	// e.g., "127.0.0.1:7650" for IPv4-only or "::1:7650" for IPv6-only.
	listener, err := net.Listen("tcp", s.config.Address)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create listener on %s", s.config.Address)
	}

	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	log.WithFields(logger.Fields{
		"at":      "(Server).createListener",
		"address": listener.Addr().String(),
	}).Info("I2PControl server listening")

	return listener, nil
}

// validateHTTPSConfig performs startup-time HTTPS checks so Start() can fail
// before reporting success when certificates are invalid.
func (s *Server) validateHTTPSConfig() error {
	if !s.config.UseHTTPS {
		return nil
	}

	if s.config.CertFile == "" || s.config.KeyFile == "" {
		log.WithFields(logger.Fields{
			"at":       "(Server).validateHTTPSConfig",
			"reason":   "missing cert or key file",
			"certFile": s.config.CertFile,
			"keyFile":  s.config.KeyFile,
		}).Error("Failed to start HTTPS server")
		return oops.Errorf("missing certificate or key file")
	}

	if _, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile); err != nil {
		return oops.Wrapf(err, "failed to load TLS certificate/key")
	}

	return nil
}

// serveOnListener runs the HTTP(S) serving loop against an already-bound listener.
func (s *Server) serveOnListener(listener net.Listener) error {
	if s.config.UseHTTPS {
		return s.httpServer.ServeTLS(listener, s.config.CertFile, s.config.KeyFile)
	}
	return s.httpServer.Serve(listener)
}

// defaultPasswordWarnInterval throttles the repeated advisory emitted when
// clients authenticate with the backward-compatibility default password.
const defaultPasswordWarnInterval = 5 * time.Minute

var (
	defaultPasswordWarnMu   sync.Mutex
	defaultPasswordWarnLast time.Time
)

// logDefaultPasswordAuth emits a rate-limited warning whenever an authenticated
// session uses the backward-compatibility default password. The first call in
// each interval window is logged; subsequent calls are suppressed so that a
// busy monitoring client does not drown the log.
func logDefaultPasswordAuth() {
	defaultPasswordWarnMu.Lock()
	defer defaultPasswordWarnMu.Unlock()
	if !defaultPasswordWarnLast.IsZero() && time.Since(defaultPasswordWarnLast) < defaultPasswordWarnInterval {
		return
	}
	defaultPasswordWarnLast = time.Now()
	log.WithFields(logger.Fields{
		"at":     "i2pcontrol.Authenticate",
		"reason": "default_password_in_use",
	}).Warn("I2PControl authenticated with default password 'itoopie' — retained for backward-compatibility; change password or set strict_auth=true in production")
}

// startTokenCleanup launches a background goroutine to periodically clean expired tokens.
func (s *Server) startTokenCleanup() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.authManager.CleanupExpiredTokens()
			}
		}
	}()
}

// Stop gracefully shuts down the server, waiting for active requests to complete.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		log.WithFields(logger.Fields{
			"at": "(Server).Stop",
		}).Info("Stopping I2PControl server")

		// Cancel context to signal goroutines
		s.cancel()

		// Shutdown HTTP server with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.WithFields(logger.Fields{
				"at":     "(Server).Stop",
				"reason": err.Error(),
			}).Error("Error during server shutdown")
		}

		// Wait for all goroutines to finish
		s.wg.Wait()

		log.WithFields(logger.Fields{
			"at": "(Server).Stop",
		}).Info("I2PControl server stopped")
	})
}

// handleRPC processes JSON-RPC requests on the /jsonrpc endpoint.
// Request flow:
// 1. Verify HTTP method is POST
// 2. Verify Content-Type is application/json
// 3. Parse JSON-RPC request
// 4. Validate authentication token (if not Authenticate method)
// 5. Dispatch to method handler
// 6. Serialize and return response
func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	s.setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	req, rpcErr := s.parseAndValidateRequest(r)
	if rpcErr != nil {
		s.writeErrorResponse(w, nil, rpcErr)
		return
	}
	if req == nil {
		// Validation error already written
		return
	}

	if rpcErr := s.validateAuthentication(req); rpcErr != nil {
		s.writeErrorResponse(w, req.ID, rpcErr)
		return
	}

	s.handleValidatedRequest(w, r, req)
}

// parseAndValidateRequest parses the request body and validates it.
func (s *Server) parseAndValidateRequest(r *http.Request) (*Request, *RPCError) {
	if rpcErr := s.validateHTTPRequest(r); rpcErr != nil {
		return nil, rpcErr
	}

	body, rpcErr := s.readRequestBody(r)
	if rpcErr != nil {
		return nil, rpcErr
	}

	req, err := ParseRequest(body)
	if err != nil {
		log.WithField("reason", err.Error()).Debug("i2pcontrol: malformed JSON-RPC request")
		return nil, NewRPCError(ErrCodeParseError, "malformed JSON-RPC request")
	}

	return req, nil
}

// handleValidatedRequest processes a validated request and writes the response.
func (s *Server) handleValidatedRequest(w http.ResponseWriter, r *http.Request, req *Request) {
	resp := s.registry.HandleParsedRequest(r.Context(), req)
	// JSON-RPC 2.0 notifications (requests with no "id") require no response.
	// HandleParsedRequest returns nil for notifications.
	if resp == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.writeResponse(w, resp)
}

// setCORSHeaders configures Cross-Origin Resource Sharing headers for JSON-RPC requests.
// Access-Control-Allow-Origin is restricted to the server's own address and scheme,
// preventing cross-site request exposure from arbitrary origins.
// Also sets security headers (X-Content-Type-Options, Strict-Transport-Security).
func (s *Server) setCORSHeaders(w http.ResponseWriter) {
	scheme := "http"
	if s.config.UseHTTPS {
		scheme = "https"
	}

	origin := fmt.Sprintf("%s://%s", scheme, s.config.Address)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Security headers (see AUDIT.md LOW finding)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if s.config.UseHTTPS {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
}

// validateHTTPRequest checks that the HTTP method is POST and Content-Type is application/json.
func (s *Server) validateHTTPRequest(r *http.Request) *RPCError {
	if r.Method != http.MethodPost {
		return NewRPCError(ErrCodeInvalidRequest, "Method must be POST")
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" && contentType != "application/json; charset=utf-8" {
		return NewRPCError(ErrCodeInvalidRequest, "Content-Type must be application/json")
	}

	return nil
}

// readRequestBody reads and returns the HTTP request body with a 1MB size limit.
func (s *Server) readRequestBody(r *http.Request) ([]byte, *RPCError) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, NewRPCError(ErrCodeInternalError, "Failed to read request body")
	}
	return body, nil
}

// validateAuthentication verifies the authentication token for non-Authenticate method calls.
func (s *Server) validateAuthentication(req *Request) *RPCError {
	if req.Method == "Authenticate" {
		return nil
	}

	var params struct {
		Token string `json:"Token"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil || params.Token == "" {
		return NewRPCError(ErrCodeAuthRequired, "No authentication token presented")
	}

	if !s.authManager.ValidateToken(params.Token) {
		return NewRPCError(ErrCodeTokenNotExist, "Authentication token does not exist or has expired")
	}

	return nil
}

// writeResponse serializes and writes a JSON-RPC response to the HTTP response writer.
func (s *Server) writeResponse(w http.ResponseWriter, resp *Response) {
	w.Header().Set("Content-Type", "application/json")

	data, err := resp.Marshal()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(Server).writeResponse",
			"reason": err.Error(),
		}).Error("Failed to marshal response")
		s.writeErrorResponse(w, resp.ID, NewRPCError(ErrCodeInternalError, "Failed to serialize response"))
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		log.WithFields(logger.Fields{
			"at":     "(Server).writeResponse",
			"reason": err.Error(),
		}).Error("Failed to write response")
	}
}

// writeErrorResponse creates and writes an error response to the HTTP response writer.
func (s *Server) writeErrorResponse(w http.ResponseWriter, id interface{}, rpcErr *RPCError) {
	resp := &Response{
		ID:      id,
		JSONRPC: "2.0",
		Error:   rpcErr,
	}

	w.Header().Set("Content-Type", "application/json")

	data, err := json.Marshal(resp)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(Server).writeErrorResponse",
			"reason": err.Error(),
		}).Error("Failed to marshal error response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK) // JSON-RPC always uses 200 OK
	if _, err := w.Write(data); err != nil {
		log.WithFields(logger.Fields{
			"at":     "(Server).writeErrorResponse",
			"reason": err.Error(),
		}).Error("Failed to write error response")
	}
}
