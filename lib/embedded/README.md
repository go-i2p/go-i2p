# lib/embedded - Embeddable I2P Router

The `embedded` package provides a clean, reusable interface for embedding I2P routers into Go applications. It extracts the router lifecycle management from `main.go` into a library that can be used programmatically.

## Overview

This package enables applications to run an I2P router as an embedded component rather than as a separate process. It provides:

- **Clean Interface**: `EmbeddedRouter` interface defines the contract for router lifecycle management
- **Thread-Safe Implementation**: `StandardEmbeddedRouter` provides safe concurrent access to router state
- **Graceful Shutdown**: Support for both graceful and immediate shutdown modes
- **Error Handling**: Comprehensive error reporting following project conventions

## Interface

```go
type EmbeddedRouter interface {
    // Configure initializes the router with the provided configuration
    Configure(cfg *config.RouterConfig) error
    
    // Start begins router operations
    Start() error
    
    // Stop performs graceful shutdown
    Stop() error
    
    // HardStop performs immediate termination
    HardStop()
}
```

## Usage

### Basic Example

```go
package main

import (
    "log"
    
    "github.com/go-i2p/go-i2p/lib/config"
    "github.com/go-i2p/go-i2p/lib/embedded"
)

func main() {
    // Load configuration
    cfg := config.DefaultRouterConfig()
    
    // Create embedded router
    router, err := embedded.NewStandardEmbeddedRouter(cfg)
    if err != nil {
        log.Fatalf("Failed to create router: %v", err)
    }
    
    // Configure the router
    if err := router.Configure(cfg); err != nil {
        log.Fatalf("Failed to configure router: %v", err)
    }
    
    // Start the router
    if err := router.Start(); err != nil {
        log.Fatalf("Failed to start router: %v", err)
    }
    
    // Wait for router to shut down
    router.Wait()
    
    // Clean up
    if err := router.Close(); err != nil {
        log.Printf("Error during cleanup: %v", err)
    }
}
```

### With Signal Handling

```go
package main

import (
    "log"
    "os"
    "os/signal"
    "syscall"
    
    "github.com/go-i2p/go-i2p/lib/config"
    "github.com/go-i2p/go-i2p/lib/embedded"
)

func main() {
    cfg := config.DefaultRouterConfig()
    
    router, err := embedded.NewStandardEmbeddedRouter(cfg)
    if err != nil {
        log.Fatalf("Failed to create router: %v", err)
    }
    
    if err := router.Configure(cfg); err != nil {
        log.Fatalf("Failed to configure router: %v", err)
    }
    
    // Set up signal handler
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    
    go func() {
        <-sigChan
        log.Println("Shutdown signal received, stopping router...")
        if err := router.Stop(); err != nil {
            log.Printf("Error during graceful stop: %v", err)
            router.HardStop()
        }
    }()
    
    if err := router.Start(); err != nil {
        log.Fatalf("Failed to start router: %v", err)
    }
    
    router.Wait()
    
    if err := router.Close(); err != nil {
        log.Printf("Error during cleanup: %v", err)
    }
}
```

### As a Service Component

```go
package myapp

import (
    "context"
    "fmt"
    
    "github.com/go-i2p/go-i2p/lib/config"
    "github.com/go-i2p/go-i2p/lib/embedded"
)

type MyI2PService struct {
    router *embedded.StandardEmbeddedRouter
    ctx    context.Context
    cancel context.CancelFunc
}

func NewMyI2PService(cfg *config.RouterConfig) (*MyI2PService, error) {
    router, err := embedded.NewStandardEmbeddedRouter(cfg)
    if err != nil {
        return nil, fmt.Errorf("failed to create router: %w", err)
    }
    
    if err := router.Configure(cfg); err != nil {
        return nil, fmt.Errorf("failed to configure router: %w", err)
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    
    return &MyI2PService{
        router: router,
        ctx:    ctx,
        cancel: cancel,
    }, nil
}

func (s *MyI2PService) Start() error {
    if err := s.router.Start(); err != nil {
        return fmt.Errorf("failed to start router: %w", err)
    }
    
    // Start your application logic here
    go s.run()
    
    return nil
}

func (s *MyI2PService) run() {
    // Your application logic that uses the I2P router
    <-s.ctx.Done()
}

func (s *MyI2PService) Stop() error {
    s.cancel()
    
    if err := s.router.Stop(); err != nil {
        return fmt.Errorf("failed to stop router: %w", err)
    }
    
    return s.router.Close()
}
```

## Lifecycle Management

The embedded router follows this lifecycle:

1. **Creation**: `NewStandardEmbeddedRouter()` - Creates router wrapper
2. **Configuration**: `Configure()` - Initializes router with configuration
3. **Startup**: `Start()` - Starts all router subsystems
4. **Running**: `Wait()` - Blocks until shutdown
5. **Shutdown**: `Stop()` - Graceful shutdown of subsystems
6. **Cleanup**: `Close()` - Releases all resources

### State Transitions

```
[Created] --Configure()--> [Configured] --Start()--> [Running]
                                                         |
                                                    Stop()/HardStop()
                                                         |
                                                         v
                                                    [Stopped] --Close()--> [Closed]
```

## Error Handling

The package follows the project's error handling conventions:

- All methods return descriptive errors using `fmt.Errorf` with `%w` for error wrapping
- State violations (e.g., starting an already running router) return errors
- Logging uses structured logging with `logger.Fields` for context

## Thread Safety

`StandardEmbeddedRouter` is thread-safe:

- All state access is protected by `sync.RWMutex`
- Methods can be called concurrently without external synchronization
- Internal router state changes are atomic

## Graceful vs. Hard Shutdown

### Graceful Shutdown (`Stop()`)

- Signals all subsystems to shut down
- Waits for in-flight operations to complete
- Allows proper cleanup of resources
- Returns error if shutdown fails

**Use this by default.**

### Hard Shutdown (`HardStop()`)

- Forces immediate termination
- Does not wait for operations to complete
- May leave resources in inconsistent state
- Does not return error

**Use only when:**
- `Stop()` hangs or fails
- Immediate termination is required
- Application is terminating abnormally

## Testing

```go
package myapp_test

import (
    "testing"
    "time"
    
    "github.com/go-i2p/go-i2p/lib/config"
    "github.com/go-i2p/go-i2p/lib/embedded"
)

func TestEmbeddedRouter(t *testing.T) {
    cfg := config.DefaultRouterConfig()
    cfg.BaseDir = t.TempDir()
    
    router, err := embedded.NewStandardEmbeddedRouter(cfg)
    if err != nil {
        t.Fatalf("Failed to create router: %v", err)
    }
    
    if err := router.Configure(cfg); err != nil {
        t.Fatalf("Failed to configure router: %v", err)
    }
    
    if err := router.Start(); err != nil {
        t.Fatalf("Failed to start router: %v", err)
    }
    
    // Verify router is running
    if !router.IsRunning() {
        t.Error("Router should be running")
    }
    
    // Let it run briefly
    time.Sleep(2 * time.Second)
    
    // Stop the router
    if err := router.Stop(); err != nil {
        t.Errorf("Failed to stop router: %v", err)
    }
    
    // Verify router is stopped
    if router.IsRunning() {
        t.Error("Router should not be running")
    }
    
    // Clean up
    if err := router.Close(); err != nil {
        t.Errorf("Failed to close router: %v", err)
    }
}
```

## Differences from Direct Router Usage

### Before (main.go direct usage)

```go
routerInstance, err := router.CreateRouter(config.RouterConfigProperties)
if err != nil {
    log.Fatalf("Failed: %v", err)
}

routerInstance.Start()
routerInstance.Wait()
routerInstance.Close()
```

### After (embedded package)

```go
router, err := embedded.NewStandardEmbeddedRouter(cfg)
if err != nil {
    log.Fatalf("Failed: %v", err)
}

router.Configure(cfg)
router.Start()
router.Wait()
router.Close()
```

### Benefits

1. **Clearer lifecycle**: Explicit Configure/Start/Stop/Close steps
2. **Better error handling**: All lifecycle methods return errors
3. **State validation**: Prevents invalid operations (e.g., starting twice)
4. **Reusability**: Can be embedded in other applications
5. **Testing**: Easier to test with explicit state management

## Implementation Notes

- The package wraps `router.Router` without modifying its behavior
- All logging follows the project's structured logging conventions
- Signal handling remains in the application layer (not in the embedded package)
- Configuration reloading is handled by the application, not the embedded router

## See Also

- `lib/router` - Core router implementation
- `lib/config` - Router configuration structures
- `main.go` - Reference implementation using embedded router
