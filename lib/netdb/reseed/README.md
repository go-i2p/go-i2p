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

#### func (Reseed) ProcessLocalZipFile

```go
func (r Reseed) ProcessLocalZipFile(filePath string) ([]router_info.RouterInfo, error)
```
ProcessLocalZipFile reads and processes a local zip reseed file

#### func (Reseed) SingleReseed

```go
func (r Reseed) SingleReseed(uri string) ([]router_info.RouterInfo, error)
```



reseed 

github.com/go-i2p/go-i2p/lib/netdb/reseed

[go-i2p template file](/template.md)
