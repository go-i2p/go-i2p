# embedded
--
    import "github.com/go-i2p/go-i2p/lib/embedded"

![embedded.svg](embedded.svg)

Package embedded provides a reusable interface for embedding I2P routers into Go
applications.

This package extracts router lifecycle management from the main application into
a library that can be used programmatically. It provides thread-safe, structured
lifecycle management for I2P router instances.

# Basic Usage

    cfg := config.DefaultRouterConfig()
    router, err := embedded.NewStandardEmbeddedRouter(cfg)
    if err != nil {
        log.Fatal(err)
    }

    if err := router.Configure(cfg); err != nil {
        log.Fatal(err)
    }

    if err := router.Start(); err != nil {
        log.Fatal(err)
    }
    defer router.Close()

    router.Wait()

# Lifecycle

The embedded router follows a strict lifecycle:

    1. Create with NewStandardEmbeddedRouter()
    2. Configure with Configure()
    3. Start with Start()
    4. Run with Wait()
    5. Stop with Stop()
    6. Cleanup with Close()

# Thread Safety

All methods are thread-safe and can be called concurrently. The implementation
uses sync.RWMutex to protect internal state.

# Error Handling

All lifecycle methods return errors that can be inspected. The package follows
the project's error handling conventions with structured logging.

# Graceful Shutdown

The Stop() method performs graceful shutdown, waiting for subsystems to complete
in-flight operations. For immediate termination, use HardStop().

## Usage

```go
var CertificatesFS embed.FS
```
CertificatesFS embeds all certificates at compile time. This eliminates runtime
file dependencies for certificate access.

#### func  ExtractCertificates

```go
func ExtractCertificates(destDir string) error
```
ExtractCertificates extracts embedded certificates to the specified directory.
This is useful for first-run setup or when external tools need file-based
access. The directory structure under destDir will mirror the embedded
structure.

#### func  ExtractReseedCertificates

```go
func ExtractReseedCertificates(destDir string) error
```
ExtractReseedCertificates extracts only the reseed certificates to the specified
directory. Unlike ExtractCertificates, this places files directly in destDir
without subdirectories.

#### func  GetCertificateByPath

```go
func GetCertificateByPath(certPath string) ([]byte, error)
```
GetCertificateByPath returns the PEM content for a certificate at the given
path. The path should be relative to the certificates directory (e.g.,
"reseed/admin_at_stormycloud.org.crt"). Returns an error if the path contains
directory traversal components.

#### func  GetFamilyCertificates

```go
func GetFamilyCertificates() (fs.FS, error)
```
GetFamilyCertificates returns the embedded family certificates as a filesystem.
The returned fs.FS is rooted at the certificates/family directory.

#### func  GetReseedCertificateByName

```go
func GetReseedCertificateByName(certFileName string) ([]byte, error)
```
GetReseedCertificateByName returns the PEM content for a specific reseed
certificate. The certFileName should be just the filename (e.g.,
"admin_at_stormycloud.org.crt"). Returns an error if the filename contains path
separators or traversal components.

#### func  GetReseedCertificates

```go
func GetReseedCertificates() (fs.FS, error)
```
GetReseedCertificates returns the embedded reseed certificates as a filesystem.
The returned fs.FS is rooted at the certificates/reseed directory.

#### func  GetSSLCertificates

```go
func GetSSLCertificates() (fs.FS, error)
```
GetSSLCertificates returns the embedded SSL certificates as a filesystem. The
returned fs.FS is rooted at the certificates/ssl directory.

#### func  ListReseedCertificates

```go
func ListReseedCertificates() ([]string, error)
```
ListReseedCertificates returns a list of all embedded reseed certificate
filenames.

#### type EmbeddedRouter

```go
type EmbeddedRouter interface {
	// Configure initializes the router with the provided configuration.
	// Must be called before Start(). Returns error if configuration is invalid
	// or if router is already configured.
	Configure(cfg *config.RouterConfig) error

	// Start begins router operations, starting all subsystems (networking,
	// tunnels, netdb, etc.). Returns error if router fails to start or if
	// called before Configure().
	Start() error

	// Stop performs graceful shutdown of the router, allowing in-flight
	// operations to complete. Returns error if shutdown fails or times out.
	Stop() error

	// HardStop performs immediate termination of the router without waiting
	// for graceful cleanup. Use only when Stop() is insufficient.
	HardStop()

	// Wait blocks until the router has stopped.
	Wait()

	// Close releases all resources held by the router. The router must be
	// stopped before Close is called.
	Close() error

	// IsRunning reports whether the router is currently operational.
	IsRunning() bool

	// IsConfigured reports whether Configure has been called successfully.
	IsConfigured() bool
}
```

EmbeddedRouter defines the interface for an embeddable I2P router instance. This
interface allows programmatic control of router lifecycle for applications that
need to embed an I2P router rather than run it as a standalone process.

#### type StandardEmbeddedRouter

```go
type StandardEmbeddedRouter struct {
}
```

StandardEmbeddedRouter is the standard implementation of EmbeddedRouter. It
wraps a router.Router instance and manages its lifecycle with proper
thread-safety and error handling.

#### func  NewStandardEmbeddedRouter

```go
func NewStandardEmbeddedRouter(cfg *config.RouterConfig) (*StandardEmbeddedRouter, error)
```
NewStandardEmbeddedRouter creates a new embedded router instance. The router is
automatically configured with the provided config. Call Start() to begin router
operations.

Returns error if the configuration is nil or invalid, or if router creation
fails.

#### func (*StandardEmbeddedRouter) Close

```go
func (e *StandardEmbeddedRouter) Close() error
```
Close releases all resources associated with the router. This should be called
after Stop() to ensure proper cleanup.

#### func (*StandardEmbeddedRouter) Configure

```go
func (e *StandardEmbeddedRouter) Configure(cfg *config.RouterConfig) error
```
Configure initializes the router with the provided configuration. This method
creates the underlying router instance but does not start it.

Note: NewStandardEmbeddedRouter already calls Configure() internally. Callers
using the constructor do NOT need to call Configure() again. Calling Configure()
on an already-configured router returns nil (no-op) to prevent errors from the
documented constructor + Configure pattern.

#### func (*StandardEmbeddedRouter) HardStop

```go
func (e *StandardEmbeddedRouter) HardStop()
```
HardStop performs immediate termination without graceful cleanup. Unlike Stop(),
this does not wait for subsystems to shut down cleanly. It calls Stop() with a
short timeout, then marks the router stopped. Use this only when Stop() fails or
when immediate termination is required.

#### func (*StandardEmbeddedRouter) IsConfigured

```go
func (e *StandardEmbeddedRouter) IsConfigured() bool
```
IsConfigured returns true if the router has been configured.

#### func (*StandardEmbeddedRouter) IsRunning

```go
func (e *StandardEmbeddedRouter) IsRunning() bool
```
IsRunning returns true if the router is currently running.

#### func (*StandardEmbeddedRouter) Start

```go
func (e *StandardEmbeddedRouter) Start() error
```
Start begins router operations. The router must be configured before calling
Start(). This method starts all router subsystems and blocks until the router is
fully started.

#### func (*StandardEmbeddedRouter) Stop

```go
func (e *StandardEmbeddedRouter) Stop() error
```
Stop performs graceful shutdown of the router. This method stops all router
subsystems and waits for them to shut down cleanly. The mutex is released before
calling router.Stop() to prevent deadlock with goroutines that call IsRunning()
during shutdown.

#### func (*StandardEmbeddedRouter) Wait

```go
func (e *StandardEmbeddedRouter) Wait()
```
Wait blocks until the router shuts down. This method can be called after Start()
to keep the router running until Stop() is called. It uses a done channel to
avoid TOCTOU races where Stop()+Close() could nil the router pointer between
releasing the read lock and calling router.Wait().



embedded 

github.com/go-i2p/go-i2p/lib/embedded

[go-i2p template file](/template.md)
