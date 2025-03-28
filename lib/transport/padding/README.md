# padding
--
    import "github.com/go-i2p/go-i2p/lib/transport/padding"

![padding.svg](padding.svg)



## Usage

#### type NullPaddingStrategy

```go
type NullPaddingStrategy struct{}
```


#### func (*NullPaddingStrategy) AddPadding

```go
func (p *NullPaddingStrategy) AddPadding(message []byte) []byte
```

#### func (*NullPaddingStrategy) RemovePadding

```go
func (p *NullPaddingStrategy) RemovePadding(message []byte) []byte
```

#### type PaddingStrategy

```go
type PaddingStrategy interface {
	AddPadding(message []byte) []byte
	RemovePadding(message []byte) []byte
}
```



padding 

github.com/go-i2p/go-i2p/lib/transport/padding
