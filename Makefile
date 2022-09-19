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

test:
	$(GO) test -v -failfast ./lib/transport/noise/...

clean:
	$(GO) clean -v
