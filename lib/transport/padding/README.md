# padding
--
    import "github.com/go-i2p/go-i2p/lib/transport/padding"

![padding.svg](padding.svg)



## Usage

#### func  Quant

```go
func Quant(input, quantum int) int
```
Quant returns the next multiple of quantum that is greater than or equal to
input. For example, Quant(10, 8) returns 16, as 16 is the next multiple of 8
that's >= 10.

#### func  QuantAdjustment

```go
func QuantAdjustment(input, quantum int) int
```
QuantAdujustment returns the amount of padding needed to make the input a
multiple of quantum. For example, if input is 10 and quantum is 8, the
adjustment would be 6 (to reach 16).

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

[go-i2p template file](/template.md)
