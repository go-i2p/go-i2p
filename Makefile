RELEASE_TAG=0.0.1
RELEASE_VERSION=${RELEASE_TAG}
RELEASE_DESCRIPTION=`cat PASTA.md`
REPO := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
CGO_ENABLED=0

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
	$(GO) build --tags netgo,osusergo -v -o $(EXE)

test: fmt
	$(GO) test -v -failfast ./lib/common/...

clean:
	$(GO) clean -v

fmt:
	find . -name '*.go' -exec gofumpt -w {} \;

info:
	echo "GOROOT: ${GOROOT}"
	echo "GO: ${GO}"
	echo "REPO: ${REPO}"

release:
	github-release release -u go-i2p -r go-i2p -n "${RELEASE_VERSION}" -t "${RELEASE_TAG}" -d "${RELEASE_DESCRIPTION}" -p

callvis:
	go-callvis -format svg -focus upgrade -group pkg,type -limit github.com/go-i2p/go-i2p github.com/go-i2p/go-i2p

godoc:
	find lib -type d -exec bash -c "ls {}/*.go && godocdown -o ./{}/doc.md ./{}" \;