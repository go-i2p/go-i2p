# sntp
--
    import "github.com/go-i2p/go-i2p/lib/util/sntp"

## Usage

```go
import "github.com/go-i2p/go-i2p/lib/util/sntp"
```

## Types

### type RouterTimestamper

```go
type RouterTimestamper struct {
    servers           []string
    priorityServers   [][]string
    listeners         []UpdateListener
    queryFrequency    time.Duration
    concurringServers int
    consecutiveFails  int
    disabled          bool
    initialized       bool
    wellSynced        bool
    isRunning         bool
    mutex             sync.Mutex
    zones             *Zones
    stopChan          chan struct{}
    waitGroup         sync.WaitGroup
    ntpClient         NTPClient
}
```

RouterTimestamper is responsible for querying NTP servers and managing time synchronization.

#### func NewRouterTimestamper

```go
func NewRouterTimestamper(client NTPClient) *RouterTimestamper
```

NewRouterTimestamper creates a new RouterTimestamper instance.

#### func (*RouterTimestamper) Start

```go
func (rt *RouterTimestamper) Start()
```

Start begins the time synchronization process.

#### func (*RouterTimestamper) Stop

```go
func (rt *RouterTimestamper) Stop()
```

Stop halts the time synchronization process.

#### func (*RouterTimestamper) AddListener

```go
func (rt *RouterTimestamper) AddListener(listener UpdateListener)
```

AddListener adds a new listener for time updates.

#### func (*RouterTimestamper) RemoveListener

```go
func (rt *RouterTimestamper) RemoveListener(listener UpdateListener)
```

RemoveListener removes a listener from receiving time updates.

#### func (*RouterTimestamper) WaitForInitialization

```go
func (rt *RouterTimestamper) WaitForInitialization()
```

WaitForInitialization blocks until the RouterTimestamper is initialized or a timeout occurs.

#### func (*RouterTimestamper) TimestampNow

```go
func (rt *RouterTimestamper) TimestampNow()
```

TimestampNow triggers an immediate time synchronization.

### type UpdateListener

```go
type UpdateListener interface {
    SetNow(now time.Time, stratum uint8)
}
```

UpdateListener is an interface that listeners must implement to receive time updates.

### type Zones

```go
type Zones struct {
    countryToZone   map[string]string
    continentToZone map[string]string
}
```

Zones manages mappings between country codes, continent codes, and NTP zones.

#### func NewZones

```go
func NewZones() *Zones
```

NewZones creates a new Zones instance and initializes it with data.

#### func (*Zones) GetZone

```go
func (z *Zones) GetZone(countryCode string) string
```

GetZone returns the NTP zone for a given country code.