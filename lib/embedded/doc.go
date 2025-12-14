// Package embedded provides a reusable interface for embedding I2P routers into Go applications.
//
// This package extracts router lifecycle management from the main application into a library
// that can be used programmatically. It provides thread-safe, structured lifecycle management
// for I2P router instances.
//
// # Basic Usage
//
//	cfg := config.DefaultRouterConfig()
//	router, err := embedded.NewStandardEmbeddedRouter(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if err := router.Configure(cfg); err != nil {
//	    log.Fatal(err)
//	}
//
//	if err := router.Start(); err != nil {
//	    log.Fatal(err)
//	}
//	defer router.Close()
//
//	router.Wait()
//
// # Lifecycle
//
// The embedded router follows a strict lifecycle:
//  1. Create with NewStandardEmbeddedRouter()
//  2. Configure with Configure()
//  3. Start with Start()
//  4. Run with Wait()
//  5. Stop with Stop()
//  6. Cleanup with Close()
//
// # Thread Safety
//
// All methods are thread-safe and can be called concurrently. The implementation
// uses sync.RWMutex to protect internal state.
//
// # Error Handling
//
// All lifecycle methods return errors that can be inspected. The package follows
// the project's error handling conventions with structured logging.
//
// # Graceful Shutdown
//
// The Stop() method performs graceful shutdown, waiting for subsystems to complete
// in-flight operations. For immediate termination, use HardStop().
package embedded
