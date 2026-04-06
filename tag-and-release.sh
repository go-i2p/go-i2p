#! /usr/bin/env sh

# takes one argument: the version to tag
VERSION=$1

if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version>"
  exit 1
fi

if [ $DRY_RUN = true ]; then
  echo "Attempting a dry run, dependencies will be updated but not checked in"
fi

git() {
  if [ $DRY_RUN = true ]; then
    echo "git $*"
  else
    command git "$@"
  fi
}

github_release() {
  if [ $DRY_RUN = true ]; then
    echo "github-release $*"
  else
    command github-release "$@"
  fi
}

# comment out all replace directives from a go.mod file and use go mod tidy
comment_out_replaces() {
  echo "Commenting out replace directives in go.mod and running go mod tidy" 1>&2
  sed -i.bak '/^replace /s/^/\/\//g' go.mod
  git add -v .
  if [ "$CHECKIN_DRY_RUN" = true ]; then
    echo "Dry run: skipping git commit for commented out replace directives"
  else
    /usr/bin/git commit -am "Comment out replace directives"
  fi
  #go mod tidy
  rm go.mod.bak
}

push() {
  /usr/bin/git push origin main || /usr/bin/git push origin trunk || /usr/bin/git push origin master
  /usr/bin/git push --tags
}

# descend into the go-i2p namespace and collect checkin hashes
cd ../
GOI2P_DIR=$(pwd)

collecthash() {
  cd "$1" && #push
  TAG_HASH=$(/usr/bin/git rev-parse HEAD)
  REMOTE=$(/usr/bin/git remote -v)
  cd "$GOI2P_DIR"
  #echo "$1 tag hash: $TAG_HASH Remote: $REMOTE" 1>&2
  echo "$TAG_HASH"
}

LOGGER_TAG_HASH=$(collecthash logger) # 0
echo "logger tag hash: $LOGGER_TAG_HASH" 1>&2
SU3_TAG_HASH=$(collecthash su3) # 0
echo "su3 tag hash: $SU3_TAG_HASH" 1>&2
CRYPTO_TAG_HASH=$(collecthash crypto) # 1
echo "crypto tag hash: $CRYPTO_TAG_HASH" 1>&2
COMMON_TAG_HASH=$(collecthash common) # 2
echo "common tag hash: $COMMON_TAG_HASH" 1>&2
NOISE_TAG_HASH=$(collecthash noise) # 3
echo "noise tag hash: $NOISE_TAG_HASH" 1>&2
GO_NOISE_TAG_HASH=$(collecthash go-noise) # 4
echo "go-noise tag hash: $GO_NOISE_TAG_HASH" 1>&2
GO_I2P_TAG_HASH=$(collecthash go-i2p) # 5
echo "go-i2p tag hash: $GO_I2P_TAG_HASH" 1>&2
GO_I2CP_TAG_HASH=$(collecthash go-i2cp) # 6
echo "go-i2cp tag hash: $GO_I2CP_TAG_HASH" 1>&2
GO_DATAGRAMS_TAG_HASH=$(collecthash go-datagrams) # 7
echo "go-datagrams tag hash: $GO_DATAGRAMS_TAG_HASH" 1>&2
GO_STREAMING_TAG_HASH=$(collecthash go-streaming) # 8
echo "go-streaming tag hash: $GO_STREAMING_TAG_HASH" 1>&2
GO_SAM_BRIDGE_TAG_HASH=$(collecthash go-sam-bridge) # 9
echo "go-sam-bridge tag hash: $GO_SAM_BRIDGE_TAG_HASH" 1>&2

echo "Collected tag hashes. Proceeding to tag version v$VERSION" 1>&2

# go get all our packages at the new version
# use go mod tidy to clean up unused deps
update_our_packages() {
  echo "Updating the packages" 1>&2
  #go get -u ./...
  echo go get "github.com/go-i2p/logger@$LOGGER_TAG_HASH" 1>&2
  go get "github.com/go-i2p/logger@$LOGGER_TAG_HASH" >/dev/null 2>/dev/null || true
  echo go get "github.com/go-i2p/su3@$SU3_TAG_HASH" 1>&2
  go get "github.com/go-i2p/su3@$SU3_TAG_HASH" >/dev/null 2>/dev/null || true
  echo go get "github.com/go-i2p/crypto@$CRYPTO_TAG_HASH" 1>&2
  go get "github.com/go-i2p/crypto@$CRYPTO_TAG_HASH" >/dev/null 2>/dev/null || true
  echo go get "github.com/go-i2p/common@$COMMON_TAG_HASH" 1>&2
  go get "github.com/go-i2p/common@$COMMON_TAG_HASH" >/dev/null 2>/dev/null || true
  echo go get "github.com/go-i2p/noise@$NOISE_TAG_HASH" 1>&2
  go get "github.com/go-i2p/noise@$NOISE_TAG_HASH" >/dev/null 2>/dev/null || true
  echo go get "github.com/go-i2p/go-noise@$GO_NOISE_TAG_HASH" 1>&2
  go get "github.com/go-i2p/go-noise@$GO_NOISE_TAG_HASH" >/dev/null 2>/dev/null || true
  echo go get "github.com/go-i2p/go-i2p@$GO_I2P_TAG_HASH" 1>&2
  go get "github.com/go-i2p/go-i2p@$GO_I2P_TAG_HASH" >/dev/null 2>/dev/null || true
  echo go get "github.com/go-i2p/go-i2cp@$GO_I2CP_TAG_HASH" 1>&2
  go get "github.com/go-i2p/go-i2cp@$GO_I2CP_TAG_HASH" >/dev/null 2>/dev/null || true
  echo go get "github.com/go-i2p/go-datagrams@$GO_DATAGRAMS_TAG_HASH" 1>&2
  go get "github.com/go-i2p/go-datagrams@$GO_DATAGRAMS_TAG_HASH" >/dev/null 2>/dev/null || true
  echo go get "github.com/go-i2p/go-streaming@$GO_STREAMING_TAG_HASH" 1>&2
  go get "github.com/go-i2p/go-streaming@$GO_STREAMING_TAG_HASH" >/dev/null 2>/dev/null || true
  echo go get "github.com/go-i2p/go-sam-bridge@$GO_SAM_BRIDGE_TAG_HASH" 1>&2
  go get "github.com/go-i2p/go-sam-bridge@$GO_SAM_BRIDGE_TAG_HASH" >/dev/null 2>/dev/null || true
  go mod tidy -v 1>&2
  go build -v ./... 1>&2
  echo "Updated our packages to v$VERSION" 1>&2
  /usr/bin/git commit -am "Update dependencies to v$VERSION"
}

cleanup() {
  /usr/bin/git push origin --delete "v$VERSION" 2> /dev/null || true
}

tagandrelease() {
  cd "$GOI2P_DIR"
  cd $1
  echo "tagging and releasing $1 v$VERSION" 1>&2
  #cleanup
  echo "Commenting out replace directives and updating our packages for $1" 1>&2
  comment_out_replaces
  echo "Updating our packages for $1" 1>&2
  update_our_packages
  if [ $DRY_RUN = true ]; then
    echo "Dry run: skipping git tag and release for $1"
    if [ "$CHECKIN_DRY_RUN" = true ]; then
      echo "Dry run: skipping git add and commit for $1"
    else
      /usr/bin/git add -v .
      /usr/bin/git commit -am "library sync for v$VERSION" 1>&2
      push
    fi
    return
  fi
  # if release nodes is less than 6 lines long, delete it and create a placeholder
  if [ -f RELEASE_NOTES.md ] && [ $(wc -l < RELEASE_NOTES.md) -lt 6 ]; then
    rm RELEASE_NOTES.md
    git add -v -f RELEASE_NOTES.md 1>&2
    git commit -m "Remove short RELEASE_NOTES.md for $1" 1>&2
  fi
  if [ ! -f RELEASE_NOTES.md ]; then
    echo "Release notes for: \`$1\` Version \`$VERSION\`" > RELEASE_NOTES.md
    echo "==============================================" >> RELEASE_NOTES.md
    echo "" >> RELEASE_NOTES.md
    echo "This file is generated automatically in order to keep git tags in sync." >> RELEASE_NOTES.md
    echo "TODO: Add RELEASE_NOTES.md for $1." >> RELEASE_NOTES.md
    echo "" >> RELEASE_NOTES.md
    git add -v -f RELEASE_NOTES.md 1>&2
    git commit -m "Add placeholder RELEASE_NOTES.md for $1" 1>&2
  fi
  # if the top line of RELEASE_NOTES does not contain $VERSION, replace it
  FIRST_LINE=$(head -n 1 RELEASE_NOTES.md)
  if ! echo "$FIRST_LINE" | grep -q "v$VERSION"; then
    REPLACEMENT_LINE="Release notes for: \`$1\` Version \`$VERSION\`"
    #sed -i.bak "1s/.*/$REPLACEMENT_LINE/" RELEASE_NOTES.md
    #rm RELEASE_NOTES.md.bak
    echo "$REPLACEMENT_LINE" > RELEASE_NOTES.md.tmp
    tail -n +2 RELEASE_NOTES.md >> RELEASE_NOTES.md.tmp
    mv RELEASE_NOTES.md.tmp RELEASE_NOTES.md
    git add -v -f RELEASE_NOTES.md 1>&2
    git commit -m "Update RELEASE_NOTES.md for v$VERSION" 1>&2
  fi
  git tag -sa "v$VERSION" -m "$1 v$VERSION" 1>&2
  TAG_HASH=$(git rev-parse "v$VERSION")
  echo "$1 v$VERSION tag hash: $TAG_HASH" 1>&2
  echo "$TAG_HASH"
  if [ -f RELEASE_NOTES.md ]; then
    github_release release \
      --user go-i2p \
      --repo "$1" \
      --tag "v$VERSION" \
      --name "go-i2p v$VERSION" \
      --description "$(cat RELEASE_NOTES.md)" 1>&2
  fi
  push > /dev/null 2>/dev/null
}

echo "Tagging and releasing version v$VERSION" 1>&2

LOGGER_TAG_HASH=$(tagandrelease logger) # 0
SU3_TAG_HASH=$(tagandrelease su3) # 1
CRYPTO_TAG_HASH=$(tagandrelease crypto) # 3
COMMON_TAG_HASH=$(tagandrelease common) # 4
NOISE_TAG_HASH=$(tagandrelease noise) # 5
GO_NOISE_TAG_HASH=$(tagandrelease go-noise) # 6
GO_I2P_TAG_HASH=$(tagandrelease go-i2p) # 7
GO_I2CP_TAG_HASH=$(tagandrelease go-i2cp) # 8
GO_DATAGRAMS_TAG_HASH=$(tagandrelease go-datagrams) # 9
GO_STREAMING_TAG_HASH=$(tagandrelease go-streaming) # 10
GO_SAM_BRIDGE_TAG_HASH=$(tagandrelease go-sam-bridge) # 11

echo "Successfully tagged and released version v$VERSION" 1>&2
