REPO := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))


ifdef GOROOT
	GO = $(GOROOT)/bin/go
endif

GO ?= $(shell which go)

ifeq ($(GOOS),windows)
	EXE := $(REPO)/go-i2p.exe
else
	EXE := $(REPO)/go-i2p
endif

build: clean $(EXE)

$(EXE):
	$(GO) build -v -o $(EXE)

test: fmt
	$(GO) test -vv -failfast ./lib/common/...

clean:
	$(GO) clean -v

fmt:
	find . -name '*.go' -exec gofmt -w -s {} \;