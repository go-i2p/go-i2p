#! /usr/bin/env sh

# takes one argument: the version to tag
VERSION=$1

# Ordered repository definitions.
# Format for each token: <repo_name>:<hash_var_name>
HASH_REPOS_PAIRS='
logger:LOGGER_TAG_HASH
elgamal:ELGAMAL_TAG_HASH
su3:SU3_TAG_HASH
crypto:CRYPTO_TAG_HASH
common:COMMON_TAG_HASH
noise:NOISE_TAG_HASH
go-nat-listener:GO_NAT_LISTENER_TAG_HASH
path:PATH_TAG_HASH
pool:POOL_TAG_HASH
go-noise:GO_NOISE_TAG_HASH
go-i2p:GO_I2P_TAG_HASH
go-i2cp:GO_I2CP_TAG_HASH
go-datagrams:GO_DATAGRAMS_TAG_HASH
go-streaming:GO_STREAMING_TAG_HASH
go-sam-bridge:GO_SAM_BRIDGE_TAG_HASH
'

# Preserve existing update ordering exactly, including duplicate "noise" updates.
UPDATE_ORDER='
logger
elgamal
su3
crypto
common
noise
go-nat-listener
path
pool
noise
go-noise
go-i2p
go-i2cp
go-datagrams
go-streaming
go-sam-bridge
'

# Preserve existing release ordering exactly, including LIBS split.
RELEASE_REPOS_LIBS='
logger:LOGGER_TAG_HASH
elgamal:ELGAMAL_TAG_HASH
su3:SU3_TAG_HASH
crypto:CRYPTO_TAG_HASH
common:COMMON_TAG_HASH
'

RELEASE_REPOS_NON_LIBS='
pool:POOL_TAG_HASH
path:PATH_TAG_HASH
noise:NOISE_TAG_HASH
go-nat-listener:GO_NAT_LISTENER_TAG_HASH
go-noise:GO_NOISE_TAG_HASH
go-i2p:GO_I2P_TAG_HASH
go-i2cp:GO_I2CP_TAG_HASH
go-datagrams:GO_DATAGRAMS_TAG_HASH
go-streaming:GO_STREAMING_TAG_HASH
go-sam-bridge:GO_SAM_BRIDGE_TAG_HASH
'

if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version>"
  exit 1
fi

if [ "$DRY_RUN" = true ]; then
  echo "Attempting a dry run, dependencies will be updated but not checked in"
fi

git() {
  if [ "$DRY_RUN" = true ]; then
    echo "git $*"
  else
    command git "$@"
  fi
}

github_release() {
  if [ "$DRY_RUN" = true ]; then
    echo "github-release $*"
  else
    command github-release "$@"
  fi
}

# comment out all replace directives from a go.mod file and use go mod tidy
comment_out_replaces() {
  echo "Commenting out replace directives in go.mod and running go mod tidy" 1>&2
  sed -i.bak '/^replace /s/^/\/\//g' go.mod
  git add -v . 1>&2
  if [ "$CHECKIN_DRY_RUN" = true ]; then
    echo "Dry run: skipping git commit for commented out replace directives" 1>&2
  else
    /usr/bin/git commit -am "Comment out replace directives" 1>&2
  fi
  #go mod tidy
  rm go.mod.bak
}

push() {
  /usr/bin/git push origin main || /usr/bin/git push origin trunk || /usr/bin/git push origin master
  /usr/bin/git push --tags --force
  /usr/bin/git push origin v$VERSION --force
}

# descend into the go-i2p namespace and collect checkin hashes
cd ../
GOI2P_DIR=$(pwd)

collecthash() {
  cd "$1" && echo "Collecting tag hash for $1" 1>&2
  sync_repo_to_latest_checked_in
  TAG_HASH=$(/usr/bin/git rev-parse HEAD)
  REMOTE=$(/usr/bin/git remote -v)
  cd "$GOI2P_DIR"
  echo "$1 tag hash: $TAG_HASH Remote: $REMOTE" 1>&2
  echo "$TAG_HASH"
}

detect_default_branch() {
  branch=$(/usr/bin/git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null | sed 's#^origin/##')
  if [ -n "$branch" ]; then
    echo "$branch"
    return 0
  fi

  if /usr/bin/git show-ref --verify --quiet refs/heads/main || /usr/bin/git show-ref --verify --quiet refs/remotes/origin/main; then
    echo "main"
    return 0
  fi
  if /usr/bin/git show-ref --verify --quiet refs/heads/trunk || /usr/bin/git show-ref --verify --quiet refs/remotes/origin/trunk; then
    echo "trunk"
    return 0
  fi
  if /usr/bin/git show-ref --verify --quiet refs/heads/master || /usr/bin/git show-ref --verify --quiet refs/remotes/origin/master; then
    echo "master"
    return 0
  fi

  echo "Could not determine default branch for $(pwd)" 1>&2
  return 1
}

sync_repo_to_latest_checked_in() {
  branch=$(detect_default_branch) || return 1
  if [ "$DRY_RUN" = true ]; then
    echo "Dry run: skipping sync to origin/$branch in $(pwd)" 1>&2
    return 0
  fi

  /usr/bin/git fetch origin "$branch" 1>&2
  /usr/bin/git checkout "$branch" 1>&2
  /usr/bin/git pull --ff-only origin "$branch" 1>&2
}

assign_var() {
  # shellcheck disable=SC2039
  eval "$1=\"$2\""
}

value_of() {
  # shellcheck disable=SC2039
  eval "printf '%s' \"\${$1}\""
}

hash_var_for_repo() {
  repo_name=$1
  for entry in $HASH_REPOS_PAIRS; do
    repo=${entry%%:*}
    var=${entry#*:}
    if [ "$repo" = "$repo_name" ]; then
      echo "$var"
      return 0
    fi
  done
  return 1
}

collect_all_hashes() {
  for entry in $HASH_REPOS_PAIRS; do
    repo=${entry%%:*}
    var=${entry#*:}
    hash=$(collecthash "$repo")
    assign_var "$var" "$hash"
    echo "$repo tag hash: $hash" 1>&2
  done
}

collect_all_hashes

echo "Collected tag hashes. Proceeding to tag version v$VERSION" 1>&2

update_by_tag_hash() {
  echo "updating $1 to tag hash $2" 1>&2
  module="github.com/go-i2p/$1"
  go get "$module@$2" 1>&2

  resolved_version=$(go list -m -f '{{.Version}}' "$module" 2>/dev/null || true)
  short_hash=$(printf '%s' "$2" | cut -c1-12)
  case "$resolved_version" in
    *"$short_hash"*)
      ;;
    *)
      echo "ERROR: $module resolved to $resolved_version (expected commit containing $short_hash)" 1>&2
      exit 1
      ;;
  esac
}

# go get all our packages at the new version
# use go mod tidy to clean up unused deps
update_our_packages() {
  echo "Updating the packages" 1>&2
  for repo in $UPDATE_ORDER; do
    var=$(hash_var_for_repo "$repo")
    hash=$(value_of "$var")
    update_by_tag_hash "$repo" "$hash"
  done
  go mod tidy -v 1>&2
  go build -v ./... 1>&2
  gofumpt -w -s -extra . 1>&2
  echo "Updated our packages to upcoming v$VERSION by specific hashes" 1>&2
  /usr/bin/git commit -am "Update dependencies to v$VERSION" 1>&2
}

update_by_version() {
  echo "updating $1 to version $2" 1>&2
  module="github.com/go-i2p/$1"
  go get "$module@$2" 1>&2

  resolved_version=$(go list -m -f '{{.Version}}' "$module" 2>/dev/null || true)
  if [ "$resolved_version" != "$2" ]; then
    echo "ERROR: $module resolved to $resolved_version (expected exactly $2)" 1>&2
    exit 1
  fi
}

# go get all our packages at the new version
# use go mod tidy to clean up unused deps
correct_our_tags() {
  echo "Updating the packages" 1>&2
  for repo in $UPDATE_ORDER; do
    update_by_version "$repo" "v$VERSION"
  done
  go mod tidy -v 1>&2
  go build -v ./... 1>&2
  gofumpt -w -s -extra . 1>&2
  echo "Updated our packages to v$VERSION" 1>&2
  /usr/bin/git commit -am "Update dependencies to v$VERSION" 1>&2
}

cleanup() {
  /usr/bin/git push origin --delete "v$VERSION" 2> /dev/null || true
}

tagandrelease() {
  cd "$GOI2P_DIR"
  cd "$1"
  echo "tagging and releasing $1 v$VERSION" 1>&2
  sync_repo_to_latest_checked_in
  #cleanup
  echo "Commenting out replace directives and updating our packages for $1" 1>&2
  comment_out_replaces
  echo "Updating our packages for $1" 1>&2
  update_our_packages
  if [ "$DRY_RUN" = true ]; then
    echo "Dry run: skipping git tag and release for $1" 1>&2
    if [ "$CHECKIN_DRY_RUN" = true ]; then
      echo "Dry run: skipping git add and commit for $1" 1>&2
    else
      /usr/bin/git add -v . 1>&2
      /usr/bin/git commit -am "library sync for v$VERSION" 1>&2
      push 1>&2
    fi
    TAG_HASH=$(/usr/bin/git rev-parse "HEAD")
    echo "$1 v$VERSION tag hash: $TAG_HASH" 1>&2
    echo "$TAG_HASH"
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
  TAG_HASH=$(/usr/bin/git rev-parse "v$VERSION")
  echo "$1 v$VERSION tag hash: $TAG_HASH" 1>&2
  echo "$TAG_HASH"
  push 1>&2
  correct_our_tags 1>&2
  if [ -f RELEASE_NOTES.md ]; then
    github_release release \
      --user go-i2p \
      --repo "$1" \
      --tag "v$VERSION" \
      --name "go-i2p v$VERSION" \
      --description "$(cat RELEASE_NOTES.md)" 1>&2
  fi
}

run_release_set() {
  for entry in $1; do
    repo=${entry%%:*}
    var=${entry#*:}
    hash=$(tagandrelease "$repo")
    assign_var "$var" "$hash"
  done
}

echo "Tagging and releasing version v$VERSION" 1>&2

#echo "tag and release output test"
#tagandrelease logger
#echo "tag and release output test complete"
#exit
run_release_set "$RELEASE_REPOS_LIBS"
if [ "$LIBS" = "true" ]; then
  echo "LIBS is true, skipping noise, go-nat-listener, go-noise, go-i2p, go-i2cp, go-datagrams, go-streaming, and go-sam-bridge" 1>&2
  exit 0
fi
run_release_set "$RELEASE_REPOS_NON_LIBS"

echo "Successfully tagged and released version v$VERSION" 1>&2
