# util
--
    import "github.com/go-i2p/go-i2p/lib/util"

![util.svg](util.svg)



## Usage

#### func  CheckFileAge

```go
func CheckFileAge(fpath string, maxAge int) bool
```
Check if a file is more than maxAge minutes old returns false if

#### func  CheckFileExists

```go
func CheckFileExists(fpath string) bool
```
Check if a file exists and is readable etc returns false if not

#### func  CloseAll

```go
func CloseAll()
```

#### func  Panicf

```go
func Panicf(format string, args ...interface{})
```
Panicf allows passing formated string to panic()

#### func  RegisterCloser

```go
func RegisterCloser(c io.Closer)
```

#### func  UserHome

```go
func UserHome() string
```



util 

github.com/go-i2p/go-i2p/lib/util

[go-i2p template file](/template.md)
