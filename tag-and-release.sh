#! /usr/bin/env sh

# takes one argument: the version to tag
VERSION=$1

if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version>"
  exit 1
fi

# comment out all replace directives from a go.mod file and use go mod tidy
comment_out_replaces() {
  sed -i.bak '/^replace /s/^/\/\//g' go.mod
  go mod tidy
  rm go.mod.bak
}

# go get all our packages at the new version
# use go mod tidy to clean up unused deps
update_our_packages() {
  go get -u ./...
  go get "github.com/go-i2p/go-i2p/logger@v$LOGGER_TAG_HASH"; true
  go get "github.com/go-i2p/go-i2p/crypto@v$CRYPTO_TAG_HASH"; true
  go get "github.com/go-i2p/go-i2p/common@v$COMMON_TAG_HASH"; true
  go get "github.com/go-i2p/go-i2p/noise@v$NOISE_TAG_HASH"; true
  go get "github.com/go-i2p/go-i2p/go-noise@v$GO_NOISE_TAG_HASH"; true
  go get "github.com/go-i2p/go-i2p/go-i2p@v$GO_I2P_TAG_HASH"; true
  go get "github.com/go-i2p/go-i2p/go-i2cp@v$GO_I2CP_TAG_HASH"; true
  go get "github.com/go-i2p/go-i2p/go-datagrams@v$GO_DATAGRAMS_TAG_HASH"; true
  go get "github.com/go-i2p/go-i2p/go-streaming@v$GO_STREAMING_TAG_HASH"; true
  go get "github.com/go-i2p/go-i2p/go-sam-bridge@v$GO_SAM_BRIDGE_TAG_HASH"; true
  go mod tidy
  git commit -am "Update dependencies to v$VERSION"
}

push() {
  git push origin main || git push origin trunk || git push origin master
  git push --tags
  sleep 20m
}

cleanup() {
  git push origin --delete "v$VERSION"
}

# descend into the go-i2p namespace and tag dependencies
cd ../
# store the go-i2p namespace directory
GOI2P_DIR=$(pwd)
# start with logger
cd logger
cleanup
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "logger v$VERSION"
LOGGER_TAG_HASH=$(git rev-parse "v$VERSION")
push
# return to go-i2p namespace
cd "$GOI2P_DIR"
# next do crypto
cd crypto
cleanup
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "crypto v$VERSION"
CRYPTO_TAG_HASH=$(git rev-parse "v$VERSION")
push
# return to go-i2p namespace
cd "$GOI2P_DIR"
# next do common
cd common
cleanup
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "common v$VERSION"
COMMON_TAG_HASH=$(git rev-parse "v$VERSION")
push
# return to go-i2p namespace
cd "$GOI2P_DIR"
# next do noise
cd noise
cleanup
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "noise v$VERSION"
NOISE_TAG_HASH=$(git rev-parse "v$VERSION")
push
# return to go-i2p namespace
cd "$GOI2P_DIR"
# next do go-noise
cd go-noise
cleanup
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "go-noise v$VERSION"
GO_NOISE_TAG_HASH=$(git rev-parse "v$VERSION")
push
# return to go-i2p namespace
cd "$GOI2P_DIR"
# finally do go-i2p
cd go-i2p
cleanup
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "go-i2p v$VERSION"
GO_I2P_TAG_HASH=$(git rev-parse "v$VERSION")
push
cd "$GOI2P_DIR"
# now start the client libraries
cd go-i2cp
cleanup
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "go-i2cp v$VERSION"
GO_I2CP_TAG_HASH=$(git rev-parse "v$VERSION")
push
cd "$GOI2P_DIR"
cd go-datagrams
cleanup
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "go-datagrams v$VERSION"
GO_DATAGRAMS_TAG_HASH=$(git rev-parse "v$VERSION")
push
cd "$GOI2P_DIR"
cd go-streaming
cleanup
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "go-streaming v$VERSION"
GO_STREAMING_TAG_HASH=$(git rev-parse "v$VERSION")
push
cd "$GOI2P_DIR"
cd go-sam-bridge
cleanup
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "go-sam-bridge v$VERSION"
GO_SAM_BRIDGE_TAG_HASH=$(git rev-parse "v$VERSION")
push
cd "$GOI2P_DIR"