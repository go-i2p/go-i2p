RELEASE_TAG=0.0.1
RELEASE_VERSION=${RELEASE_TAG}
RELEASE_DESCRIPTION=`cat PASTA.md`
REPO := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
CGO_ENABLED=0
export DEBUG_I2P=debug

ifdef GOROOT
	GO = $(GOROOT)/bin/go
endif

GO ?= $(shell which go)

ifeq ($(GOOS),windows)
	EXE := $(REPO)/go-i2p.exe
else
	EXE := $(REPO)/go-i2p
endif

#check for gofumpt
check_gofumpt:
	@which gofumpt > /dev/null 2>&1 || (echo "gofumpt is required but not installed. Please install it from https://github.com/mvdan/gofumpt."; exit 1)

build: clean $(EXE)

$(EXE):
	$(GO) build --tags netgo,osusergo -v -o $(EXE)

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

godoc:
	./callgraph.sh
	find . -name 'README.md' -exec git add -v {} \;
	git commit -am "GODOC UPDATE CHECKIN"
