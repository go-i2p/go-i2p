package netdb

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// routerInfoFileMode is the mode for the router's own router.info file. Unlike
// key material it is public data (a RouterInfo is a signed advertisement), so
// it is world-readable: external tooling running as another user — a
// monitoring dashboard parsing the ident hash — must be able to read it.
const routerInfoFileMode os.FileMode = 0644

// WriteRouterInfoFile serializes ri and writes it to path as a single
// base64-encoded line, the same encoding i2pd uses for its router.info. The
// write is atomic (temp file + rename) so a reader never observes a partial
// file while the RouterInfo is being republished.
//
// The file lets external tooling derive the router's ident hash without
// reaching into the NetDB: parsing it back with ReadRouterInfoFile yields the
// same hash as the routerInfo-<base64hash>.dat file this router's peers store.
//
// An empty path disables the write and returns nil.
func WriteRouterInfoFile(path string, ri router_info.RouterInfo) error {
	if path == "" {
		return nil
	}

	data, err := ri.Bytes()
	if err != nil {
		return oops.Wrapf(err, "failed to serialize RouterInfo for %s", path)
	}
	encoded := base64.StdEncoding.EncodeToString(data) + "\n"

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return oops.Wrapf(err, "failed to create directory for router info file %s", path)
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".router.info-*.tmp")
	if err != nil {
		return oops.Wrapf(err, "failed to create temp router info file in %s", filepath.Dir(path))
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.WriteString(encoded); err != nil {
		tmp.Close()
		return oops.Wrapf(err, "failed to write router info file %s", tmpName)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return oops.Wrapf(err, "failed to sync router info file %s", tmpName)
	}
	if err := tmp.Close(); err != nil {
		return oops.Wrapf(err, "failed to close router info file %s", tmpName)
	}
	if err := os.Chmod(tmpName, routerInfoFileMode); err != nil {
		return oops.Wrapf(err, "failed to chmod router info file %s", tmpName)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return oops.Wrapf(err, "failed to rename router info file into place at %s", path)
	}

	return nil
}

// ReadRouterInfoFile decodes a file written by WriteRouterInfoFile back into a
// RouterInfo. Surrounding whitespace is tolerated so a trailing newline (or a
// reader that strips it) parses identically.
func ReadRouterInfoFile(path string) (router_info.RouterInfo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return router_info.RouterInfo{}, oops.Wrapf(err, "failed to read router info file %s", path)
	}
	data, err := base64.StdEncoding.DecodeString(removeAllWhitespace(string(raw)))
	if err != nil {
		return router_info.RouterInfo{}, oops.Wrapf(err, "router info file %s is not valid base64", path)
	}
	ri, _, err := router_info.ReadRouterInfo(data)
	if err != nil {
		return router_info.RouterInfo{}, oops.Wrapf(err, "failed to parse RouterInfo from %s", path)
	}
	return ri, nil
}

// removeAllWhitespace removes all ASCII whitespace, not just leading and
// trailing bytes: a wrapped or copy-pasted line inside the file should not make
// the router's own identity unparseable.
func removeAllWhitespace(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// logRouterInfoFileWrite records the router.info write at debug level, with a
// warning on failure: the file is observability data, so a failure must not
// stop publishing.
func logRouterInfoFileWrite(path string, err error) {
	if err == nil {
		log.WithFields(logger.Fields{
			"at":   "publishOurRouterInfo",
			"path": path,
		}).Debug("wrote own RouterInfo to disk")
		return
	}
	log.WithError(err).WithFields(logger.Fields{
		"at":   "publishOurRouterInfo",
		"path": path,
	}).Warn("failed to write own RouterInfo to disk")
}
