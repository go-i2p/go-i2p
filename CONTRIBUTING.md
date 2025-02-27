# Contributing

Thanks for taking a look at go-i2p!  Please reach out if you have any questions or need help getting started.

## Getting Started

Install required dependencies

This example assumes Ubuntu or Debian based Linux, a reasonably modern version.
The instructions will be similar for other Linux distributions with slightly different package managers and package names.

```sh
# For obtaining, modifying, compiling, and tracking changes to go-i2p, install:
sudo apt-get install golang-go make git
# If you want to generate markdown versions of the godoc locally, also install:
go install github.com/robertkrimen/godocdown/godocdown@master
# If you want to generate call graphs locally, also install:
go install github.com/ofabry/go-callvis@master
```

On Windows, one must install the latest versions of Go and Git Bash from their respective sources.

## Set up your workspace:

```sh
github_username=yourusername
cd $(go env GOPATH)
git clone git@github.com:$github_username/go-i2p github.com/go-i2p/go-i2p
github.com/go-i2p/go-i2p
```

Fork go-i2p and clone it into your workspace.  Make sure you can execute `go test ./...` in the project's root directory.  At that point you should have everything you need to start making changes and opening pull requests.

## I2P Specifications

The I2P community maintains up-to-date [specifications](https://geti2p.net/spec) of most of the application, which are being used to create go-i2p.  Currently, most the of common data structures (located in `lib/common/`) have been implemented and tested, and serve as good examples.

## Testing

`go test ./...`

## Conventions

#### Errors

We use oops to provide context to the errors we return. Do not use `errors.New` or `fmt.Errorf`. Wrap raw errors in oops errors. When an error is recieved, used oops to supplement the log output.

#### Logging

Logrus is used for logging across all of go-i2p. We have a small extension of logrus at https://github.com/go-i2p/logger which we use to add a "Fail Fast mode." We are mostly converted over to using it. 

All log statements should contain an `at` fields and a `reason` field.  Here is a good example from the go-i2p implementation of a LeaseSet:

```go
log.WithFields(log.Fields{
	"at":           "(LeaseSet) PublicKey",
	"data_len":     remainer_len,
	"required_len": LEASE_SET_PUBKEY_SIZE,
	"reason":       "not enough data",
}).Error("error parsing public key")
```

#### Testing

Testify is used to assert test cases in all tests in go-i2p for simplicity.  Here is an example from the RouterInfo tests:

```go
func TestRouterAddressCountReturnsCorrectCount(t *testing.T) {
	assert := assert.New(t)

	router_info := buildFullRouterInfo()
	count, err := router_info.RouterAddressCount()
	assert.Nil(err)
	assert.Equal(1, count, "RouterInfo.RouterAddressCount() did not return correct count")
}
```

## Pull Requests

Pull requests should pass all tests, test all new behavior, and be correctly formatted by `gofumpt -w -s -extra` before merge.  Feel free to open incomplete pull requests and ask for help and advice.