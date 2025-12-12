# bootstrap
--
    import "github.com/go-i2p/go-i2p/lib/bootstrap"

![bootstrap.svg](bootstrap.svg)

provides generic interfaces for initial bootstrap into network and network
### reseeding

## Usage

#### func  GetRouterHashString

```go
func GetRouterHashString(ri router_info.RouterInfo) string
```
GetRouterHashString returns a hex string representation of the RouterInfo's
IdentHash This is a helper function to avoid duplication in logging

#### func  HasDirectNTCP2Connectivity

```go
func HasDirectNTCP2Connectivity(ri router_info.RouterInfo) bool
```
HasDirectNTCP2Connectivity checks if a RouterInfo has at least one NTCP2 address
with direct connectivity (host and port keys present, not introducer-only). This
pre-filtering function prevents ERROR logs from the common package when
attempting to extract host keys from introducer-only addresses.

CRITICAL FIX #1: Pre-filter bootstrap peers before validation to prevent
"RouterAddress missing required host key" errors for introducer-only addresses.

#### func  ValidateNTCP2Address

```go
func ValidateNTCP2Address(addr *router_address.RouterAddress) error
```
ValidateNTCP2Address validates NTCP2-specific requirements

#### func  ValidateRouterAddress

```go
func ValidateRouterAddress(addr *router_address.RouterAddress) error
```
ValidateRouterAddress validates a single RouterAddress Returns nil if valid,
otherwise returns an error describing the validation failure

#### func  ValidateRouterInfo

```go
func ValidateRouterInfo(ri router_info.RouterInfo) error
```
ValidateRouterInfo performs comprehensive validation on a RouterInfo Returns nil
if valid, otherwise returns an error describing the validation failure

#### type Bootstrap

```go
type Bootstrap interface {
	// get more peers for bootstrap
	// try obtaining at most n router infos
	// if n is 0 then try obtaining as many router infos as possible
	// returns nil and error if we cannot fetch ANY router infos
	// returns a slice of router infos containing n or fewer router infos
	GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error)
}
```

interface defining a way to bootstrap into the i2p network

#### type CompositeBootstrap

```go
type CompositeBootstrap struct {
}
```

CompositeBootstrap implements the Bootstrap interface by trying multiple
bootstrap methods in sequence: 1. Local reseed file (if specified) - highest
priority 2. Remote reseed servers 3. Local netDb directories - fallback

#### func  NewCompositeBootstrap

```go
func NewCompositeBootstrap(cfg *config.BootstrapConfig) *CompositeBootstrap
```
NewCompositeBootstrap creates a new composite bootstrap with file, reseed, and
local netDb fallback

#### func (*CompositeBootstrap) GetPeers

```go
func (cb *CompositeBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error)
```
GetPeers implements the Bootstrap interface by trying file first (if specified),
then reseed, then falling back to local netDb if both fail

#### type FileBootstrap

```go
type FileBootstrap struct {
}
```

FileBootstrap implements the Bootstrap interface using a local zip or su3 file

#### func  NewFileBootstrap

```go
func NewFileBootstrap(filePath string) *FileBootstrap
```
NewFileBootstrap creates a new file bootstrap with the provided file path

#### func (*FileBootstrap) GetPeers

```go
func (fb *FileBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error)
```
GetPeers implements the Bootstrap interface by reading RouterInfos from a local
file

#### type LocalNetDbBootstrap

```go
type LocalNetDbBootstrap struct {
}
```

LocalNetDbBootstrap implements the Bootstrap interface by reading RouterInfos
from a local netDb directory (Java I2P or i2pd compatible)

#### func  NewLocalNetDbBootstrap

```go
func NewLocalNetDbBootstrap(cfg *config.BootstrapConfig) *LocalNetDbBootstrap
```
NewLocalNetDbBootstrap creates a new local netDb bootstrap with default search
paths

#### func  NewLocalNetDbBootstrapWithPaths

```go
func NewLocalNetDbBootstrapWithPaths(paths []string) *LocalNetDbBootstrap
```
NewLocalNetDbBootstrapWithPaths creates a new local netDb bootstrap with custom
paths

#### func (*LocalNetDbBootstrap) GetPeers

```go
func (lb *LocalNetDbBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error)
```
GetPeers implements the Bootstrap interface by reading RouterInfos from local
netDb

#### type ReseedBootstrap

```go
type ReseedBootstrap struct {
}
```

ReseedBootstrap implements the Bootstrap interface using HTTP reseeding

#### func  NewReseedBootstrap

```go
func NewReseedBootstrap(config *config.BootstrapConfig) *ReseedBootstrap
```
NewReseedBootstrap creates a new reseeder with the provided configuration

#### func (*ReseedBootstrap) GetPeers

```go
func (rb *ReseedBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error)
```
GetPeers implements the Bootstrap interface by obtaining RouterInfos from
configured reseed servers

#### type ValidationStats

```go
type ValidationStats struct {
	TotalProcessed     int
	ValidRouterInfos   int
	InvalidRouterInfos int
	InvalidReasons     map[string]int
}
```

ValidationStats tracks statistics about RouterInfo validation during bootstrap

#### func  NewValidationStats

```go
func NewValidationStats() *ValidationStats
```
NewValidationStats creates a new ValidationStats instance

#### func (*ValidationStats) LogSummary

```go
func (vs *ValidationStats) LogSummary(phase string)
```
LogSummary logs a summary of the validation statistics

#### func (*ValidationStats) RecordInvalid

```go
func (vs *ValidationStats) RecordInvalid(reason string)
```
RecordInvalid increments the invalid RouterInfo count and tracks the reason

#### func (*ValidationStats) RecordValid

```go
func (vs *ValidationStats) RecordValid()
```
RecordValid increments the valid RouterInfo count

#### func (*ValidationStats) ValidityRate

```go
func (vs *ValidationStats) ValidityRate() float64
```
ValidityRate returns the percentage of valid RouterInfos



bootstrap 

github.com/go-i2p/go-i2p/lib/bootstrap

[go-i2p template file](/template.md)
