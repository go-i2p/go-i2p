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
LOGGER_TAG_HASH=$(collecthash logger) # 0
CRYPTO_TAG_HASH=$(collecthash crypto) # 1
COMMON_TAG_HASH=$(collecthash common) # 2
NOISE_TAG_HASH=$(collecthash noise) # 3
GO_NOISE_TAG_HASH=$(collecthash go-noise) # 4
GO_I2P_TAG_HASH=$(collecthash go-i2p) # 5
GO_I2CP_TAG_HASH=$(collecthash go-i2cp) # 6
GO_DATAGRAMS_TAG_HASH=$(collecthash go-datagrams) # 7
GO_STREAMING_TAG_HASH=$(collecthash go-streaming) # 8
GO_SAM_BRIDGE_TAG_HASH=$(collecthash go-sam-bridge) # 9

echo "Collected tag hashes. Proceeding to tag version v$VERSION" 1>&2

# go get all our packages at the new version
# use go mod tidy to clean up unused deps
update_our_packages() {
  go get -u ./...
  go get "github.com/go-i2p/logger@$LOGGER_TAG_HASH" >/dev/null 2>/dev/null || true
  go get "github.com/go-i2p/crypto@$CRYPTO_TAG_HASH" >/dev/null 2>/dev/null || true
  go get "github.com/go-i2p/common@$COMMON_TAG_HASH" >/dev/null 2>/dev/null || true
  go get "github.com/go-i2p/noise@$NOISE_TAG_HASH" >/dev/null 2>/dev/null || true
  go get "github.com/go-i2p/go-noise@$GO_NOISE_TAG_HASH" >/dev/null 2>/dev/null || true
  go get "github.com/go-i2p/go-i2p@$GO_I2P_TAG_HASH" >/dev/null 2>/dev/null || true
  go get "github.com/go-i2p/go-i2cp@$GO_I2CP_TAG_HASH" >/dev/null 2>/dev/null || true
  go get "github.com/go-i2p/go-datagrams@$GO_DATAGRAMS_TAG_HASH" >/dev/null 2>/dev/null || true
  go get "github.com/go-i2p/go-streaming@$GO_STREAMING_TAG_HASH" >/dev/null 2>/dev/null || true
  go get "github.com/go-i2p/go-sam-bridge@$GO_SAM_BRIDGE_TAG_HASH" >/dev/null 2>/dev/null || true
  go mod tidy >/dev/null 2>/dev/null || true
  echo "Updated our packages to v$VERSION" 1>&2
  git commit -am "Update dependencies to v$VERSION"
}

cleanup() {
  git push origin --delete "v$VERSION" 2> /dev/null || true
}

tagandrelease() {
  cd "$GOI2P_DIR"
  cd $1
  #cleanup
  comment_out_replaces
  update_our_packages
  git tag -sa "v$VERSION" -m "$1 v$VERSION" 1>&2
  TAG_HASH=$(git rev-parse "v$VERSION")
  echo "$1 v$VERSION tag hash: $TAG_HASH" 1>&2
  echo "$TAG_HASH"
  if [ -f RELEASE_NOTES.md ]; then
    github-release release \
      --user go-i2p \
      --repo "$1" \
      --tag "v$VERSION" \
      --name "go-i2p v$VERSION" \
      --description "$(cat RELEASE_NOTES.md)" 1>&2
  fi
  push
}

echo "Tagging and releasing version v$VERSION" 1>&2

LOGGER_TAG_HASH=$(tagandrelease logger) # 0
CRYPTO_TAG_HASH=$(tagandrelease crypto) # 1
COMMON_TAG_HASH=$(tagandrelease common) # 2
NOISE_TAG_HASH=$(tagandrelease noise) # 3
GO_NOISE_TAG_HASH=$(tagandrelease go-noise) # 4
GO_I2P_TAG_HASH=$(tagandrelease go-i2p) # 5
GO_I2CP_TAG_HASH=$(tagandrelease go-i2cp) # 6
GO_DATAGRAMS_TAG_HASH=$(tagandrelease go-datagrams) # 7
GO_STREAMING_TAG_HASH=$(tagandrelease go-streaming) # 8
GO_SAM_BRIDGE_TAG_HASH=$(tagandrelease go-sam-bridge) # 9

echo "Successfully tagged and released version v$VERSION" 1>&2