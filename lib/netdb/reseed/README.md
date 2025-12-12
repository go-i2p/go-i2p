# reseed
--
    import "github.com/go-i2p/go-i2p/lib/netdb/reseed"

![reseed.svg](reseed.svg)



## Usage

```go
const (
	DefaultDialTimeout = 30 * time.Second // 30 seconds for HTTP requests
	DefaultKeepAlive   = 30 * time.Second // 30 seconds keep-alive
)
```

```go
const (
	I2pUserAgent = "Wget/1.11.4"
)
```

#### type Reseed

```go
type Reseed struct {
	net.Dialer
}
```


#### func  NewReseed

```go
func NewReseed() *Reseed
```

#### func (Reseed) ProcessLocalSU3File

```go
func (r Reseed) ProcessLocalSU3File(filePath string) ([]router_info.RouterInfo, error)
```
ProcessLocalSU3File reads and processes a local SU3 reseed file

#### func (Reseed) ProcessLocalSU3FileWithLimit

```go
func (r Reseed) ProcessLocalSU3FileWithLimit(filePath string, limit int) ([]router_info.RouterInfo, error)
```
ProcessLocalSU3FileWithLimit reads and processes a local SU3 reseed file with a
limit on RouterInfos parsed. If limit <= 0, all RouterInfos are parsed (same as
ProcessLocalSU3File). This prevents loading excessive RouterInfos into memory
when only a small number is needed.

#### func (Reseed) ProcessLocalZipFile

```go
func (r Reseed) ProcessLocalZipFile(filePath string) ([]router_info.RouterInfo, error)
```
ProcessLocalZipFile reads and processes a local zip reseed file

#### func (Reseed) ProcessLocalZipFileWithLimit

```go
func (r Reseed) ProcessLocalZipFileWithLimit(filePath string, limit int) ([]router_info.RouterInfo, error)
```
ProcessLocalZipFileWithLimit reads and processes a local zip reseed file with a
limit on RouterInfos parsed. If limit <= 0, all RouterInfos are parsed (same as
ProcessLocalZipFile). This prevents loading excessive RouterInfos into memory
when only a small number is needed.

#### func (Reseed) SingleReseed

```go
func (r Reseed) SingleReseed(uri string) ([]router_info.RouterInfo, error)
```



reseed 

github.com/go-i2p/go-i2p/lib/netdb/reseed

[go-i2p template file](/template.md)
