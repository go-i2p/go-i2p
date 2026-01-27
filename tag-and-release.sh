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

push() {
  git push origin main || git push origin trunk || git push origin master
  git push --tags
  sleep 1m
}

# descend into the go-i2p namespace and collect checkin hashes
cd ../
GOI2P_DIR=$(pwd)

collecthash() {
  cd "$1" && #push
  TAG_HASH=$(git rev-parse HEAD)
  REMOTE=$(git remote -v)
  cd "$GOI2P_DIR"
  echo "$TAG_HASH"
  echo "$1 tag hash: $TAG_HASH" 1>&2
  echo "Remote: $REMOTE" 1>&2
}
LOGGER_TAG_HASH=$(collecthash logger)
CRYPTO_TAG_HASH=$(collecthash crypto)
COMMON_TAG_HASH=$(collecthash common)
NOISE_TAG_HASH=$(collecthash noise)
GO_NOISE_TAG_HASH=$(collecthash go-noise)
GO_I2P_TAG_HASH=$(collecthash go-i2p)
GO_I2CP_TAG_HASH=$(collecthash go-i2cp)
GO_DATAGRAMS_TAG_HASH=$(collecthash go-datagrams)
GO_STREAMING_TAG_HASH=$(collecthash go-streaming)
GO_SAM_BRIDGE_TAG_HASH=$(collecthash go-sam-bridge)

echo "Collected tag hashes. Proceeding to tag version v$VERSION" 1>&2

# go get all our packages at the new version
# use go mod tidy to clean up unused deps
update_our_packages() {
  go get -u ./...
  go get "github.com/go-i2p/logger@$LOGGER_TAG_HASH" || echo PANIC go get logger failed in $(pwd); exit 1
  go get "github.com/go-i2p/crypto@$CRYPTO_TAG_HASH" || echo PANIC go get crypto failed in $(pwd); exit 1
  go get "github.com/go-i2p/common@$COMMON_TAG_HASH" || echo PANIC go get common failed in $(pwd); exit 1
  go get "github.com/go-i2p/noise@$NOISE_TAG_HASH" || echo PANIC go get noise failed in $(pwd); exit 1
  go get "github.com/go-i2p/go-noise@$GO_NOISE_TAG_HASH" || echo PANIC go get go-noise failed in $(pwd); exit 1
  go get "github.com/go-i2p/go-i2p@$GO_I2P_TAG_HASH" || echo PANIC go get go-i2p failed in $(pwd); exit 1
  go get "github.com/go-i2p/go-i2cp@$GO_I2CP_TAG_HASH" || echo PANIC go get go-i2cp failed in $(pwd); exit 1
  go get "github.com/go-i2p/go-datagrams@$GO_DATAGRAMS_TAG_HASH" || echo PANIC go get go-datagrams failed in $(pwd); exit 1
  go get "github.com/go-i2p/go-streaming@$GO_STREAMING_TAG_HASH" || echo PANIC go get go-streaming failed in $(pwd); exit 1
  go get "github.com/go-i2p/go-sam-bridge@$GO_SAM_BRIDGE_TAG_HASH" || echo PANIC go get go-sam-bridge failed in $(pwd); exit 1
  go mod tidy || echo PANIC go mod tidy failed in $(pwd); exit 1
  git commit -am "Update dependencies to v$VERSION"
}

cleanup() {
  git push origin --delete "v$VERSION"
}

cd "$GOI2P_DIR"

# start with logger
cd logger
cleanup
comment_out_replaces
update_our_packages
exit 1


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