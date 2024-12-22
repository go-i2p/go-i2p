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

# Include test definitions
-include doc/tests/*.mk

test: 		   test-string-all \
               test-mapping-all \
               test-crypto-aes-all \
               test-crypto-dsa-all \
               test-crypto-ed25519-all \
               test-crypto-elg-all \
               test-crypto-hmac-all \
               test-i2np-header-all \
               test-key-cert-all \
               test-keys-cert-all \
               test-lease-set-all \
               test-noise-transport-all \
               test-router-address-all \
               test-router-info-all \
               test-su3-all \
               test-tunnel-all \
               test-base32-encode-decode-not-mangled \
               test-base64-encode-decode-not-mangled \
               test-lease-all \
               test-date-time-from-milliseconds

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

