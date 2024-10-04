# data
--
    import "github.com/go-i2p/go-i2p/lib/common/data"

Package data implements common data structures used in higher level structures.

## Usage

```go
const DATE_SIZE = 8
```
DATE_SIZE is the length in bytes of an I2P Date.

```go
const MAX_INTEGER_SIZE = 8
```
MAX_INTEGER_SIZE is the maximum length of an I2P integer in bytes.

```go
const STRING_MAX_SIZE = 255
```
STRING_MAX_SIZE is the maximum number of bytes that can be stored in an I2P
string

#### func  PrintErrors

```go
func PrintErrors(errs []error)
```
PrintErrors prints a formatted list of errors to the console.

#### func  WrapErrors

```go
func WrapErrors(errs []error) error
```
WrapErrors compiles a slice of errors and returns them wrapped together as a
single error.

#### type Date

```go
type Date [8]byte
```

Date is the represenation of an I2P Date.

https://geti2p.net/spec/common-structures#date

#### func  NewDate

```go
func NewDate(data []byte) (date *Date, remainder []byte, err error)
```
NewDate creates a new Date from []byte using ReadDate. Returns a pointer to Date
unlike ReadDate.

#### func  ReadDate

```go
func ReadDate(data []byte) (date Date, remainder []byte, err error)
```
ReadDate creates a Date from []byte using the first DATE_SIZE bytes. Any data
after DATE_SIZE is returned as a remainder.

#### func (Date) Bytes

```go
func (i Date) Bytes() []byte
```
Bytes returns the raw []byte content of a Date.

#### func (Date) Int

```go
func (i Date) Int() int
```
Int returns the Date as a Go integer.

#### func (Date) Time

```go
func (date Date) Time() (date_time time.Time)
```
Time takes the value stored in date as an 8 byte big-endian integer representing
the number of milliseconds since the beginning of unix time and converts it to a
Go time.Time struct.

#### type Hash

```go
type Hash [32]byte
```

Hash is the represenation of an I2P Hash.

https://geti2p.net/spec/common-structures#hash

#### func  HashData

```go
func HashData(data []byte) (h Hash)
```
HashData returns the SHA256 sum of a []byte input as Hash.

#### func  HashReader

```go
func HashReader(r io.Reader) (h Hash, err error)
```
HashReader returns the SHA256 sum from all data read from an io.Reader. return
error if one occurs while reading from reader

#### func (Hash) Bytes

```go
func (h Hash) Bytes() [32]byte
```

#### type I2PString

```go
type I2PString []byte
```

I2PString is the represenation of an I2P String.

https://geti2p.net/spec/common-structures#string

#### func  ReadI2PString

```go
func ReadI2PString(data []byte) (str I2PString, remainder []byte, err error)
```
ReadI2PString returns I2PString from a []byte. The remaining bytes after the
specified length are also returned. Returns a list of errors that occurred
during parsing.

#### func  ToI2PString

```go
func ToI2PString(data string) (str I2PString, err error)
```
ToI2PString converts a Go string to an I2PString. Returns error if the string
exceeds STRING_MAX_SIZE.

#### func (I2PString) Data

```go
func (str I2PString) Data() (data string, err error)
```
Data returns the I2PString content as a string trimmed to the specified length
and not including the length byte. Returns error encountered by Length.

#### func (I2PString) Length

```go
func (str I2PString) Length() (length int, err error)
```
Length returns the length specified in the first byte. Returns error if the
specified does not match the actual length or the string is otherwise invalid.

#### type Integer

```go
type Integer []byte
```

Integer is the represenation of an I2P Integer.

https://geti2p.net/spec/common-structures#integer

#### func  NewInteger

```go
func NewInteger(bytes []byte, size int) (integer *Integer, remainder []byte, err error)
```
NewInteger creates a new Integer from []byte using ReadInteger. Limits the
length of the created Integer to MAX_INTEGER_SIZE. Returns a pointer to Integer
unlike ReadInteger.

#### func  NewIntegerFromInt

```go
func NewIntegerFromInt(value int, size int) (integer *Integer, err error)
```
NewIntegerFromInt creates a new Integer from a Go integer of a specified []byte
length.

#### func  ReadInteger

```go
func ReadInteger(bytes []byte, size int) (Integer, []byte)
```
ReadInteger returns an Integer from a []byte of specified length. The remaining
bytes after the specified length are also returned.

#### func (Integer) Bytes

```go
func (i Integer) Bytes() []byte
```
Bytes returns the raw []byte content of an Integer.

#### func (Integer) Int

```go
func (i Integer) Int() int
```
Int returns the Date as a Go integer

#### type Mapping

```go
type Mapping struct {
}
```

Mapping is the represenation of an I2P Mapping.

https://geti2p.net/spec/common-structures#mapping

#### func  GoMapToMapping

```go
func GoMapToMapping(gomap map[string]string) (mapping *Mapping, err error)
```
GoMapToMapping converts a Go map of unformatted strings to *Mapping.

#### func  NewMapping

```go
func NewMapping(bytes []byte) (values *Mapping, remainder []byte, err []error)
```
NewMapping creates a new *Mapping from []byte using ReadMapping. Returns a
pointer to Mapping unlike ReadMapping.

#### func  ReadMapping

```go
func ReadMapping(bytes []byte) (mapping Mapping, remainder []byte, err []error)
```
ReadMapping returns Mapping from a []byte. The remaining bytes after the
specified length are also returned. Returns a list of errors that occurred
during parsing.

#### func  ValuesToMapping

```go
func ValuesToMapping(values MappingValues) *Mapping
```
ValuesToMapping creates a *Mapping using MappingValues. The values are sorted in
the order defined in mappingOrder.

#### func (*Mapping) Data

```go
func (mapping *Mapping) Data() []byte
```
Data returns a Mapping in its []byte form.

#### func (*Mapping) HasDuplicateKeys

```go
func (mapping *Mapping) HasDuplicateKeys() bool
```
HasDuplicateKeys returns true if two keys in a mapping are identical.

#### func (Mapping) Values

```go
func (mapping Mapping) Values() MappingValues
```
Values returns the values contained in a Mapping as MappingValues.

#### type MappingValues

```go
type MappingValues [][2]I2PString
```

MappingValues represents the parsed key value pairs inside of an I2P Mapping.

#### func  ReadMappingValues

```go
func ReadMappingValues(remainder []byte, map_length Integer) (values *MappingValues, remainder_bytes []byte, errs []error)
```
ReadMappingValues returns *MappingValues from a []byte. The remaining bytes
after the specified length are also returned. Returns a list of errors that
occurred during parsing.

#### func (MappingValues) Get

```go
func (m MappingValues) Get(key I2PString) I2PString
```
