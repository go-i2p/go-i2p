#! /usr/bin/env sh

# takes one argument: the version to tag
VERSION=$1

# Resolve paths relative to this script so invocation cwd does not matter.
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

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
cd "$SCRIPT_DIR/.." || exit 1
GOI2P_DIR=$(pwd)

collecthash() {
  cd "$GOI2P_DIR/$1" || {
    echo "ERROR: repository directory not found: $GOI2P_DIR/$1" 1>&2
    return 1
  }
  echo "Collecting tag hash for $1" 1>&2
  sync_repo_to_latest_checked_in || {
    echo "ERROR: failed to sync repository $1" 1>&2
    return 1
  }
  TAG_HASH=$(/usr/bin/git rev-parse HEAD)
  if [ -z "$TAG_HASH" ]; then
    echo "ERROR: failed to collect HEAD hash for $1" 1>&2
    return 1
  fi
  REMOTE=$(/usr/bin/git remote -v)
  cd "$GOI2P_DIR"
  echo "$1 tag hash: $TAG_HASH Remote: $REMOTE" 1>&2
  echo "$TAG_HASH"
}

detect_default_branch() {
  if /usr/bin/git show-ref --verify --quiet refs/heads/main || /usr/bin/git show-ref --verify --quiet refs/remotes/origin/main; then
    echo "main"
    return 0
  fi

  branch=$(/usr/bin/git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null | sed 's#^origin/##')
  if [ -n "$branch" ]; then
    echo "$branch"
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
  if [ "$CHECKIN_DRY_RUN" = true ]; then
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

remote_has_hash() {
  repo=$1
  hash=$2
  /usr/bin/git -C "$GOI2P_DIR/$repo" ls-remote origin 2>/dev/null | awk '{print $1}' | grep -qi "^$hash$"
}

ensure_hash_published() {
  repo=$1
  hash=$2

  if remote_has_hash "$repo" "$hash"; then
    return 0
  fi

  if [ "$CHECKIN_DRY_RUN" = true ]; then
    echo "ERROR: $repo hash $hash is not available on origin during dry-run" 1>&2
    return 1
  fi

  cd "$GOI2P_DIR/$repo" || return 1
  branch=$(detect_default_branch) || return 1
  echo "Publishing missing hash $hash for $repo via origin/$branch" 1>&2
  /usr/bin/git push origin "$branch" 1>&2 || return 1
  cd "$GOI2P_DIR" || return 1

  if ! remote_has_hash "$repo" "$hash"; then
    echo "ERROR: $repo hash $hash still not visible on origin after push" 1>&2
    return 1
  fi
  return 0
}

collect_all_hashes() {
  for entry in $HASH_REPOS_PAIRS; do
    repo=${entry%%:*}
    var=${entry#*:}
    hash=$(collecthash "$repo") || exit 1
    ensure_hash_published "$repo" "$hash" || exit 1
    assign_var "$var" "$hash"
    echo "$repo tag hash: $hash" 1>&2
  done
}

collect_all_hashes

echo "Collected tag hashes. Proceeding to tag version v$VERSION" 1>&2

verify_resolved_by_hash() {
  repo=$1
  hash=$2
  module="github.com/go-i2p/$repo"
  resolved_version=$(go list -m -f '{{.Version}}' "$module" 2>/dev/null || true)
  short_hash=$(printf '%s' "$hash" | cut -c1-12)
  case "$resolved_version" in
    *"$short_hash"*)
      ;;
    *)
      # Some modules resolve to a tag instead of a pseudo-version. Accept that
      # only when the resolved tag points to the exact expected commit.
      resolved_tag_hash=$(cd "$GOI2P_DIR/$repo" 2>/dev/null && /usr/bin/git rev-list -n 1 "$resolved_version" 2>/dev/null || true)
      if [ "$resolved_tag_hash" != "$hash" ]; then
        echo "ERROR: $module resolved to $resolved_version (expected commit $hash)" 1>&2
        exit 1
      fi
      ;;
  esac
}

resolve_version_for_hash() {
  module=$1
  hash=$2
  GOPROXY=direct go mod download -json "$module@$hash" 2>/dev/null | sed -n 's/^[[:space:]]*"Version": "\([^"]*\)",/\1/p' | head -n 1
}

ensure_version_downloadable() {
  module=$1
  version=$2
  GOPROXY=direct go mod download "$module@$version" 1>&2
}

drop_local_replace() {
  module=$1
  /usr/bin/go mod edit -dropreplace "$module" 2>/dev/null || true
}

force_update_by_hash() {
  repo=$1
  hash=$2
  module="github.com/go-i2p/$repo"

  echo "updating $repo to tag hash $hash" 1>&2
  if [ -z "$hash" ]; then
    echo "ERROR: empty tag hash for $module" 1>&2
    exit 1
  fi

  drop_local_replace "$module"
  resolved_version=$(resolve_version_for_hash "$module" "$hash")
  if [ -z "$resolved_version" ]; then
    echo "ERROR: could not resolve pseudo-version for $module@$hash" 1>&2
    exit 1
  fi

  if ! ensure_version_downloadable "$module" "$resolved_version"; then
    echo "ERROR: direct hash download failed for $module@$hash" 1>&2
    exit 1
  fi

  /usr/bin/go mod edit -require "$module@$resolved_version"
  verify_resolved_by_hash "$repo" "$hash"
}

force_update_by_version() {
  repo=$1
  version=$2
  module="github.com/go-i2p/$repo"

  echo "updating $repo to version $version" 1>&2
  drop_local_replace "$module"
  if ! ensure_version_downloadable "$module" "$version"; then
    echo "ERROR: direct version update failed for $module@$version" 1>&2
    exit 1
  fi
  /usr/bin/go mod edit -require "$module@$version"
  verify_resolved_by_version "$repo" "$version"
}

# go get all our packages at the new version
# use go mod tidy to clean up unused deps
update_our_packages() {
  echo "Updating the packages" 1>&2
  current_repo=$(basename "$(pwd)")
  for repo in $UPDATE_ORDER; do
    if [ "$repo" = "$current_repo" ]; then
      echo "Skipping self-update for $repo" 1>&2
      continue
    fi
    var=$(hash_var_for_repo "$repo")
    hash=$(value_of "$var")
    force_update_by_hash "$repo" "$hash"
  done

  # Reconcile once more so later module updates cannot undo earlier pins.
  echo "Reconciling all hash-pinned updates" 1>&2
  for repo in $UPDATE_ORDER; do
    if [ "$repo" = "$current_repo" ]; then
      continue
    fi
    var=$(hash_var_for_repo "$repo")
    hash=$(value_of "$var")
    force_update_by_hash "$repo" "$hash"
  done

  go mod tidy -v 1>&2
  go build -v ./... 1>&2
  gofumpt -w -s -extra . 1>&2
  echo "Updated our packages to upcoming v$VERSION by specific hashes" 1>&2
  if [ "$CHECKIN_DRY_RUN" = true ]; then
    echo "Dry run: skipping dependency update commit" 1>&2
  else
    /usr/bin/git commit -am "Update dependencies to v$VERSION" 1>&2
  fi
}

verify_resolved_by_version() {
  repo=$1
  expected_version=$2
  module="github.com/go-i2p/$repo"
  resolved_version=$(go list -m -f '{{.Version}}' "$module" 2>/dev/null || true)
  if [ "$resolved_version" != "$expected_version" ]; then
    echo "ERROR: $module resolved to $resolved_version (expected exactly $expected_version)" 1>&2
    exit 1
  fi
}

# go get all our packages at the new version
# use go mod tidy to clean up unused deps
correct_our_tags() {
  echo "Updating the packages" 1>&2
  current_repo=$(basename "$(pwd)")
  for repo in $UPDATE_ORDER; do
    if [ "$repo" = "$current_repo" ]; then
      echo "Skipping self-update for $repo" 1>&2
      continue
    fi
    force_update_by_version "$repo" "v$VERSION"
  done

  # Reconcile once more so later module updates cannot undo earlier pins.
  echo "Reconciling all version-pinned updates" 1>&2
  for repo in $UPDATE_ORDER; do
    if [ "$repo" = "$current_repo" ]; then
      continue
    fi
    force_update_by_version "$repo" "v$VERSION"
  done

  go mod tidy -v 1>&2
  go build -v ./... 1>&2
  gofumpt -w -s -extra . 1>&2
  echo "Updated our packages to v$VERSION" 1>&2
  if [ "$CHECKIN_DRY_RUN" = true ]; then
    echo "Dry run: skipping dependency update commit" 1>&2
  else
    /usr/bin/git commit -am "Update dependencies to v$VERSION" 1>&2
  fi
}

cleanup() {
  /usr/bin/git push origin --delete "v$VERSION" 2> /dev/null || true
}

tagandrelease() {
  cd "$GOI2P_DIR"
  cd "$1"
  hash_var=$(hash_var_for_repo "$1" || true)
  START_HASH=$(value_of "$hash_var")
  if [ -z "$START_HASH" ]; then
    START_HASH=$(/usr/bin/git rev-parse HEAD)
  fi
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
    echo "$1 v$VERSION dry-run hash: $START_HASH" 1>&2
    echo "$START_HASH"
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
    hash=$(tagandrelease "$repo") || {
      echo "ERROR: tag and release failed for $repo" 1>&2
      exit 1
    }
    if [ -z "$hash" ]; then
      echo "ERROR: empty tag hash returned for $repo" 1>&2
      exit 1
    fi
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
