# signals
--
    import "github.com/go-i2p/go-i2p/lib/util/signals"

![signals.svg](signals.svg)



## Usage

#### func  Handle

```go
func Handle()
```

#### func  RegisterInterruptHandler

```go
func RegisterInterruptHandler(f Handler)
```

#### func  RegisterReloadHandler

```go
func RegisterReloadHandler(f Handler)
```

#### type Handler

```go
type Handler func()
```



signals 

github.com/go-i2p/go-i2p/lib/util/signals
