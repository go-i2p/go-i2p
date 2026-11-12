// Tests for publishing the router's own RouterInfo to a router.info file.
//
// External tooling (a monitoring dashboard, a topology collector) derives the
// router's ident hash by parsing that file, the same way it parses i2pd's
// router.info. These tests pin the round-trip: what we write must parse back
// to the same identity, and it must be written even when the network publish
// cannot proceed.
package netdb

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFilePublishingProvider returns a provider handing out a real, keystore
// constructed RouterInfo (the placeholder helper in this package returns an
// empty RI, which is intentionally invalid).
func newFilePublishingProvider(t *testing.T) *mockRouterInfoProvider {
	t.Helper()
	ri := createValidRouterInfo(t)
	return &mockRouterInfoProvider{routerInfo: &ri}
}

// TestWriteReadRouterInfoFileRoundTrip verifies the file we publish parses back
// into the same RouterInfo with the same ident hash. A consumer that cannot
// reproduce our hash is the exact failure the testnet dashboard hit.
func TestWriteReadRouterInfoFileRoundTrip(t *testing.T) {
	ri := createValidRouterInfo(t)
	path := filepath.Join(t.TempDir(), "router.info")

	require.NoError(t, WriteRouterInfoFile(path, ri))

	written, err := ReadRouterInfoFile(path)
	require.NoError(t, err)

	wantHash, err := ri.IdentHash()
	require.NoError(t, err)
	gotHash, err := written.IdentHash()
	require.NoError(t, err)
	assert.Equal(t, wantHash.String(), gotHash.String(),
		"the file must parse back to this router's own ident hash")
}

// TestWriteRouterInfoFileSingleLineBase64 pins the encoding: one base64 line,
// which is what i2pd writes and what consumers split on newlines expecting.
func TestWriteRouterInfoFileSingleLineBase64(t *testing.T) {
	ri := createValidRouterInfo(t)
	path := filepath.Join(t.TempDir(), "router.info")

	require.NoError(t, WriteRouterInfoFile(path, ri))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	assert.NotContains(t, string(raw[:len(raw)-1]), "\n",
		"the encoded RouterInfo must be a single line")
	assert.Equal(t, byte('\n'), raw[len(raw)-1], "the file should end with a newline")
}

// TestReadRouterInfoFileToleratesWhitespace verifies a wrapped or copy-pasted
// file still yields an identity rather than a parse error.
func TestReadRouterInfoFileToleratesWhitespace(t *testing.T) {
	ri := createValidRouterInfo(t)
	path := filepath.Join(t.TempDir(), "router.info")

	require.NoError(t, WriteRouterInfoFile(path, ri))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("  \n"+string(raw)+"\t\n"), 0o644))

	if _, err := ReadRouterInfoFile(path); err != nil {
		t.Fatalf("surrounding whitespace must not break parsing: %v", err)
	}
}

// TestWriteRouterInfoFileCreatesParentDir verifies the write does not require
// the operator to pre-create the config directory.
func TestWriteRouterInfoFileCreatesParentDir(t *testing.T) {
	ri := createValidRouterInfo(t)
	path := filepath.Join(t.TempDir(), "nested", "config", "router.info")

	require.NoError(t, WriteRouterInfoFile(path, ri))
	require.FileExists(t, path)
}

// TestWriteRouterInfoFileEmptyPathDisabled verifies an empty path disables the
// write rather than failing, which is how an operator opts out.
func TestWriteRouterInfoFileEmptyPathDisabled(t *testing.T) {
	ri := createValidRouterInfo(t)
	require.NoError(t, WriteRouterInfoFile("", ri))
}

// TestReadRouterInfoFileMissingFile verifies a missing file errors rather than
// returning a zero RouterInfo a consumer might read as a valid identity.
func TestReadRouterInfoFileMissingFile(t *testing.T) {
	if _, err := ReadRouterInfoFile(filepath.Join(t.TempDir(), "absent.info")); err == nil {
		t.Fatal("a missing router.info must be an error")
	}
}

// TestReadRouterInfoFileGarbage verifies a non-base64 file errors clearly.
func TestReadRouterInfoFileGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "router.info")
	require.NoError(t, os.WriteFile(path, []byte("not base64 at all: @@@\n"), 0o644))

	if _, err := ReadRouterInfoFile(path); err == nil {
		t.Fatal("garbage router.info must be an error")
	}
}

// TestPublishOurRouterInfoWritesFile verifies the publish loop writes the file
// when a path is configured, and that the file's hash matches what the router
// considers its own identity.
func TestPublishOurRouterInfoWritesFile(t *testing.T) {
	provider := newFilePublishingProvider(t)
	publisher := NewPublisher(newMockNetDB(), nil, nil, provider, DefaultPublisherConfig())
	path := filepath.Join(t.TempDir(), "router.info")
	publisher.SetRouterInfoFilePath(path)

	publisher.publishOurRouterInfo()

	require.FileExists(t, path, "publishing must leave a router.info behind")

	written, err := ReadRouterInfoFile(path)
	require.NoError(t, err)

	wantHash, err := provider.routerInfo.IdentHash()
	require.NoError(t, err)
	gotHash, err := written.IdentHash()
	require.NoError(t, err)
	assert.Equal(t, wantHash.String(), gotHash.String())
}

// TestPublishOurRouterInfoNoPathWritesNothing verifies the default (no path
// configured) leaves the filesystem untouched, so behaviour is unchanged for
// anyone who does not opt in.
func TestPublishOurRouterInfoNoPathWritesNothing(t *testing.T) {
	provider := newFilePublishingProvider(t)
	publisher := NewPublisher(newMockNetDB(), nil, nil, provider, DefaultPublisherConfig())
	path := filepath.Join(t.TempDir(), "router.info")

	publisher.publishOurRouterInfo()

	assert.NoFileExists(t, path, "no path configured means no file")
	assert.Equal(t, 1, provider.callCount, "publishing still happened")
}

// TestPublishOurRouterInfoSkipsFileWhenInvalid verifies an invalid RouterInfo
// never reaches the file: writing a zero identity would hand consumers a hash
// that matches nothing.
func TestPublishOurRouterInfoSkipsFileWhenInvalid(t *testing.T) {
	empty := router_info.RouterInfo{}
	provider := &mockRouterInfoProvider{routerInfo: &empty}
	publisher := NewPublisher(newMockNetDB(), nil, nil, provider, DefaultPublisherConfig())
	path := filepath.Join(t.TempDir(), "router.info")
	publisher.SetRouterInfoFilePath(path)

	publisher.publishOurRouterInfo()

	assert.NoFileExists(t, path, "an invalid RouterInfo must not be published to disk")
}
