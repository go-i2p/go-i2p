package i2pcontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/logger"
)

// Server provides an HTTP/HTTPS endpoint for I2PControl JSON-RPC requests.
// It integrates authentication, method dispatch, and graceful shutdown.
type Server struct {
	config      *config.I2PControlConfig
	authManager *AuthManager
	registry    *MethodRegistry
	stats       RouterStatsProvider
	httpServer  *http.Server
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
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
	registry := registerRPCHandlers(stats, authManager)

	server := &Server{
		config:      cfg,
		authManager: authManager,
		registry:    registry,
		stats:       stats,
		ctx:         ctx,
		cancel:      cancel,
	}

	server.httpServer = createHTTPServer(cfg, server)
	return server, nil
}

// validateServerConfig checks that required server configuration parameters are valid.
// Returns an error if config is nil, stats is nil, or password is empty.
func validateServerConfig(cfg *config.I2PControlConfig, stats RouterStatsProvider) error {
	if cfg == nil {
		return fmt.Errorf("i2pcontrol: config cannot be nil")
	}
	if stats == nil {
		return fmt.Errorf("i2pcontrol: stats provider cannot be nil")
	}
	if cfg.Password == "" {
		return fmt.Errorf("i2pcontrol: password cannot be empty")
	}
	return nil
}

// initializeAuthManager creates and initializes the authentication manager with the given password.
// Returns the auth manager or an error if initialization fails.
func initializeAuthManager(password string) (*AuthManager, error) {
	authManager, err := NewAuthManager(password)
	if err != nil {
		return nil, fmt.Errorf("i2pcontrol: failed to create auth manager: %w", err)
	}
	return authManager, nil
}

// registerRPCHandlers creates a method registry and registers all RPC handlers.
// Returns the configured registry with Echo, GetRate, RouterInfo, Authenticate, RouterManager, NetworkSetting, and I2PControl handlers.
func registerRPCHandlers(stats RouterStatsProvider, authManager *AuthManager) *MethodRegistry {
	registry := NewMethodRegistry()

	registry.Register("Echo", NewEchoHandler())
	registry.Register("GetRate", NewGetRateHandler(stats))
	registry.Register("RouterInfo", NewRouterInfoHandler(stats))

	registry.Register("Authenticate", RPCHandlerFunc(func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		var req struct {
			API      int    `json:"API"`
			Password string `json:"Password"`
		}

		if err := json.Unmarshal(params, &req); err != nil {
			return nil, NewRPCErrorWithData(ErrCodeInvalidParams, "invalid parameters", err.Error())
		}

		if req.API != 1 {
			return nil, NewRPCError(ErrCodeInvalidParams, "unsupported API version")
		}

		token, err := authManager.Authenticate(req.Password, 10*time.Minute)
		if err != nil {
			return nil, NewRPCError(ErrCodeAuthFailed, err.Error())
		}

		return map[string]interface{}{
			"API":   req.API,
			"Token": token,
		}, nil
	}))

	registry.Register("RouterManager", NewRouterManagerHandler(stats.GetRouterControl()))
	registry.Register("NetworkSetting", NewNetworkSettingHandler(stats))
	registry.Register("I2PControl", NewI2PControlHandler(authManager))

	return registry
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
		log.Info("I2PControl server is disabled")
		return nil
	}

	s.startHTTPServer()
	s.startTokenCleanup()

	return nil
}

// startHTTPServer launches the HTTP or HTTPS server in a background goroutine.
func (s *Server) startHTTPServer() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		var err error
		if s.config.UseHTTPS {
			err = s.startHTTPSServer()
		} else {
			err = s.startPlainHTTPServer()
		}

		if err != nil && err != http.ErrServerClosed {
			log.WithFields(logger.Fields{
				"at":     "(Server).startHTTPServer",
				"reason": err.Error(),
			}).Error("I2PControl server error")
		}
	}()
}

// startHTTPSServer validates HTTPS configuration and starts the TLS server.
func (s *Server) startHTTPSServer() error {
	if s.config.CertFile == "" || s.config.KeyFile == "" {
		log.WithFields(logger.Fields{
			"at":       "(Server).startHTTPSServer",
			"reason":   "missing cert or key file",
			"certFile": s.config.CertFile,
			"keyFile":  s.config.KeyFile,
		}).Error("Failed to start HTTPS server")
		return fmt.Errorf("missing certificate or key file")
	}

	log.WithFields(logger.Fields{
		"at":       "(Server).startHTTPSServer",
		"address":  s.config.Address,
		"protocol": "HTTPS",
	}).Info("Starting I2PControl server")

	return s.httpServer.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
}

// startPlainHTTPServer starts the HTTP server without TLS.
func (s *Server) startPlainHTTPServer() error {
	log.WithFields(logger.Fields{
		"at":       "(Server).startPlainHTTPServer",
		"address":  s.config.Address,
		"protocol": "HTTP",
	}).Info("Starting I2PControl server")

	return s.httpServer.ListenAndServe()
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

	if rpcErr := s.validateHTTPRequest(r); rpcErr != nil {
		s.writeErrorResponse(w, nil, rpcErr)
		return
	}

	body, rpcErr := s.readRequestBody(r)
	if rpcErr != nil {
		s.writeErrorResponse(w, nil, rpcErr)
		return
	}

	req, err := ParseRequest(body)
	if err != nil {
		s.writeErrorResponse(w, nil, NewRPCError(ErrCodeParseError, err.Error()))
		return
	}

	if rpcErr := s.validateAuthentication(req); rpcErr != nil {
		s.writeErrorResponse(w, req.ID, rpcErr)
		return
	}

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
func (s *Server) setCORSHeaders(w http.ResponseWriter) {
	scheme := "http"
	if s.config.UseHTTPS {
		scheme = "https"
	}

	origin := fmt.Sprintf("%s://%s", scheme, s.config.Address)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
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
		return NewRPCError(ErrCodeInvalidParams, "Missing or invalid Token parameter")
	}

	if !s.authManager.ValidateToken(params.Token) {
		return NewRPCError(ErrCodeAuthRequired, "Invalid or expired authentication token")
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
