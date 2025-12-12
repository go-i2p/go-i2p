# util
--
    import "github.com/go-i2p/go-i2p/lib/util"

![util.svg](util.svg)



## Usage

#### func  CheckFileAge

```go
func CheckFileAge(fpath string, maxAge int) bool
```
CheckFileAge checks if a file is older than maxAge minutes. Returns false if the
file does not exist or on stat error. Returns true if file exists and its
modification time is older than maxAge minutes.

#### func  CheckFileExists

```go
func CheckFileExists(fpath string) bool
```
Check if a file exists and is readable etc returns false if not

#### func  CloseAll

```go
func CloseAll()
```
CloseAll closes all registered io.Closer instances and clears the list. This
function is thread-safe.

#### func  Panicf

```go
func Panicf(format string, args ...interface{})
```
Panicf allows passing formated string to panic()

#### func  RegisterCloser

```go
func RegisterCloser(c io.Closer)
```
RegisterCloser registers an io.Closer to be closed during shutdown. This
function is thread-safe.

#### func  UserHome

```go
func UserHome() string
```



util 

github.com/go-i2p/go-i2p/lib/util

[go-i2p template file](/template.md)
