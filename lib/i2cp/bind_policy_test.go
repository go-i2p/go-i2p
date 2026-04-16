package i2cp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestServer_StartFailsClosedOnNonLoopbackTCPWithoutAuth asserts that the I2CP
// server refuses to start on a non-loopback TCP listener when no authenticator
// has been configured. See AUDIT.md HIGH — "I2CP authentication is optional
// and plaintext..." (2026-04-16). The loopback case remains permissive for
// backward-compatibility with go-sam-bridge and friends.
func TestServer_StartFailsClosedOnNonLoopbackTCPWithoutAuth(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "loopback_allowed", addr: "127.0.0.1:0", wantErr: false},
		{name: "localhost_allowed", addr: "localhost:0", wantErr: false},
		{name: "wildcard_refused", addr: "0.0.0.0:17688", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := NewServer(&ServerConfig{
				ListenAddr:  tc.addr,
				Network:     "tcp",
				MaxSessions: 10,
			})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			err = srv.Start()
			if tc.wantErr {
				if err == nil {
					srv.Stop()
					t.Fatal("expected Start to refuse non-loopback bind without auth")
				}
				if !strings.Contains(err.Error(), "refusing") {
					t.Fatalf("expected refusal error, got %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("expected Start to succeed on loopback, got %v", err)
			}
			_ = srv.Stop()
		})
	}
}

// TestServer_UnixSocketPermissions asserts the I2CP server chmods its Unix
// socket to 0o600 so only the owning user can connect. See AUDIT.md MEDIUM
// — "Unix-domain socket permissions for the I2CP listener...".
func TestServer_UnixSocketPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets not supported on Windows")
	}
	sockPath := filepath.Join(t.TempDir(), "i2cp.sock")
	srv, err := NewServer(&ServerConfig{
		ListenAddr:  sockPath,
		Network:     "unix",
		MaxSessions: 10,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected socket mode 0o600, got %#o", perm)
	}
}
