#! /usr/bin/env sh

# fail on any error
set -e

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
  go get "github.com/eyedeekay/go-i2p/logger@v$VERSION"
  go get "github.com/eyedeekay/go-i2p/crypto@v$VERSION"
  go get "github.com/eyedeekay/go-i2p/common@v$VERSION"
  go get "github.com/eyedeekay/go-i2p/noise@v$VERSION"
  go get "github.com/eyedeekay/go-i2p/go-noise@v$VERSION"
  go get "github.com/eyedeekay/go-i2p@v$VERSION"
  go mod tidy
}

# descend into the go-i2p namespace and tag dependencies
cd ../
# store the go-i2p namespace directory
GOI2P_DIR=$(pwd)
# start with logger
cd logger
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "logger v$VERSION"
# return to go-i2p namespace
cd "$GOI2P_DIR"
# next do crypto
cd crypto
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "crypto v$VERSION"
# return to go-i2p namespace
cd "$GOI2P_DIR"
# next do common
cd common
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "common v$VERSION"
# return to go-i2p namespace
cd "$GOI2P_DIR"
# next do noise
cd noise
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "noise v$VERSION"
# return to go-i2p namespace
cd "$GOI2P_DIR"
# next do go-noise
cd go-noise
comment_out_replaces
update_our_packages
git tag -sa "v$VERSION" -m "go-noise v$VERSION"
# return to go-i2p namespace
cd "$GOI2P_DIR"
comment_out_replaces
update_our_packages
# finally do go-i2p
git tag -sa "v$VERSION" -m "go-i2p v$VERSION