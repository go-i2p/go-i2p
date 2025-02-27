# sntp
--
    import "github.com/go-i2p/go-i2p/lib/util/time/sntp"

![sntp.svg](sntp)



## Usage

#### type DefaultNTPClient

```go
type DefaultNTPClient struct{}
```


#### func (*DefaultNTPClient) QueryWithOptions

```go
func (c *DefaultNTPClient) QueryWithOptions(host string, options ntp.QueryOptions) (*ntp.Response, error)
```

#### type NTPClient

```go
type NTPClient interface {
	QueryWithOptions(host string, options ntp.QueryOptions) (*ntp.Response, error)
}
```


#### type RouterTimestamper

```go
type RouterTimestamper struct {
}
```


#### func  NewRouterTimestamper

```go
func NewRouterTimestamper(client NTPClient) *RouterTimestamper
```

#### func (*RouterTimestamper) AddListener

```go
func (rt *RouterTimestamper) AddListener(listener UpdateListener)
```

#### func (*RouterTimestamper) GetCurrentTime

```go
func (rt *RouterTimestamper) GetCurrentTime() time.Time
```

#### func (*RouterTimestamper) RemoveListener

```go
func (rt *RouterTimestamper) RemoveListener(listener UpdateListener)
```

#### func (*RouterTimestamper) Start

```go
func (rt *RouterTimestamper) Start()
```

#### func (*RouterTimestamper) Stop

```go
func (rt *RouterTimestamper) Stop()
```

#### func (*RouterTimestamper) TimestampNow

```go
func (rt *RouterTimestamper) TimestampNow()
```

#### func (*RouterTimestamper) WaitForInitialization

```go
func (rt *RouterTimestamper) WaitForInitialization()
```

#### type UpdateListener

```go
type UpdateListener interface {
	SetNow(now time.Time, stratum uint8)
}
```

UpdateListener is an interface that listeners must implement to receive time
updates.

#### type Zones

```go
type Zones struct {
}
```


#### func  NewZones

```go
func NewZones() *Zones
```

#### func (*Zones) GetZone

```go
func (z *Zones) GetZone(countryCode string) string
```



sntp

github.com/go-i2p/go-i2p/lib/util/time/sntp
