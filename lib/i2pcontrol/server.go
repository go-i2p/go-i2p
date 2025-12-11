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
	if cfg == nil {
		return nil, fmt.Errorf("i2pcontrol: config cannot be nil")
	}
	if stats == nil {
		return nil, fmt.Errorf("i2pcontrol: stats provider cannot be nil")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("i2pcontrol: password cannot be empty")
	}

	// Initialize authentication manager
	authManager, err := NewAuthManager(cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("i2pcontrol: failed to create auth manager: %w", err)
	}

	// Create context for server lifecycle
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize method registry
	registry := NewMethodRegistry()

	// Register all RPC handlers
	registry.Register("Echo", NewEchoHandler())
	registry.Register("GetRate", NewGetRateHandler(stats))
	registry.Register("RouterInfo", NewRouterInfoHandler(stats))

	// Register Authenticate handler with access to auth manager
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

	// RouterManager and NetworkSetting will be registered when interfaces are ready
	// registry.Register("RouterManager", NewRouterManagerHandler(stats))
	// registry.Register("NetworkSetting", NewNetworkSettingHandler(stats))

	// Create HTTP server
	mux := http.NewServeMux()
	server := &Server{
		config:      cfg,
		authManager: authManager,
		registry:    registry,
		stats:       stats,
		ctx:         ctx,
		cancel:      cancel,
	}

	mux.HandleFunc("/jsonrpc", server.handleRPC)

	server.httpServer = &http.Server{
		Addr:         cfg.Address,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return server, nil
}

// Start begins listening for HTTP/HTTPS requests on the configured address.
// It returns immediately after starting the server in a goroutine.
func (s *Server) Start() error {
	if !s.config.Enabled {
		log.Info("I2PControl server is disabled")
		return nil
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		var err error
		if s.config.UseHTTPS {
			if s.config.CertFile == "" || s.config.KeyFile == "" {
				log.WithFields(logger.Fields{
					"at":       "(Server).Start",
					"reason":   "missing cert or key file",
					"certFile": s.config.CertFile,
					"keyFile":  s.config.KeyFile,
				}).Error("Failed to start HTTPS server")
				return
			}
			log.WithFields(logger.Fields{
				"at":       "(Server).Start",
				"address":  s.config.Address,
				"protocol": "HTTPS",
			}).Info("Starting I2PControl server")
			err = s.httpServer.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
		} else {
			log.WithFields(logger.Fields{
				"at":       "(Server).Start",
				"address":  s.config.Address,
				"protocol": "HTTP",
			}).Info("Starting I2PControl server")
			err = s.httpServer.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.WithFields(logger.Fields{
				"at":     "(Server).Start",
				"reason": err.Error(),
			}).Error("I2PControl server error")
		}
	}()

	// Start token cleanup goroutine
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

	return nil
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
	// Set CORS headers for cross-origin requests
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle OPTIONS preflight request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Verify HTTP method
	if r.Method != http.MethodPost {
		s.writeErrorResponse(w, nil, NewRPCError(ErrCodeInvalidRequest, "Method must be POST"))
		return
	}

	// Verify Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" && contentType != "application/json; charset=utf-8" {
		s.writeErrorResponse(w, nil, NewRPCError(ErrCodeInvalidRequest, "Content-Type must be application/json"))
		return
	}

	// Read request body
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // Limit to 1MB
	if err != nil {
		s.writeErrorResponse(w, nil, NewRPCError(ErrCodeInternalError, "Failed to read request body"))
		return
	}
	defer r.Body.Close()

	// Parse JSON-RPC request
	req, err := ParseRequest(body)
	if err != nil {
		s.writeErrorResponse(w, nil, NewRPCError(ErrCodeParseError, err.Error()))
		return
	}

	// Validate authentication token (except for Authenticate method)
	if req.Method != "Authenticate" {
		// Parse params to extract Token
		var params struct {
			Token string `json:"Token"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || params.Token == "" {
			s.writeErrorResponse(w, req.ID, NewRPCError(ErrCodeInvalidParams, "Missing or invalid Token parameter"))
			return
		}

		if !s.authManager.ValidateToken(params.Token) {
			s.writeErrorResponse(w, req.ID, NewRPCError(ErrCodeAuthRequired, "Invalid or expired authentication token"))
			return
		}
	}

	// Dispatch to method handler
	resp := s.registry.HandleRequest(r.Context(), body)

	// Write response
	s.writeResponse(w, resp)
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
