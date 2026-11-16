package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// documentedNotHonored lists config keys that are intentionally parsed but not
// yet wired to a behavior, and are DOCUMENTED as such in config.yaml.example.
// The C1 readiness work wired every other knob; these two back a tunnel
// liveness-testing subsystem that does not exist yet, so they are allowed to
// remain inert. Adding a key here is a deliberate decision that must be
// reflected in config.yaml.example ("not yet honored").
var documentedNotHonored = map[string]bool{
	"tunnel.test_interval": true,
	"tunnel.test_timeout":  true,
}

// TestEveryConfigKeyHasConsumer is the C1 "no dead knob" CI guard.
//
// A config knob is "dead" when an operator can set it but it never reaches
// behavior — the failure mode the C1 audit found across ~35 knobs. This test
// enumerates every key registered by setDefaults() and asserts each one has at
// least one consumer OUTSIDE lib/config (the package that only parses/validates
// config). A key with no consumer and no documented "not yet honored" note fails
// the build, so a newly-added knob that is parsed but never wired cannot slip
// back in silently.
//
// Consumer detection: for each key we derive the likely Go field identifier(s)
// (CamelCase, with acronym normalization) and search every non-test .go file
// outside lib/config for an exact token occurrence. This mirrors how the router
// actually reads config (cfg.Section.Field), so it is a faithful proxy for
// "reaches behavior".
func TestEveryConfigKeyHasConsumer(t *testing.T) {
	viper.Reset()
	setDefaults()
	keys := viper.AllKeys()
	if len(keys) < 50 {
		t.Fatalf("expected many registered config keys, got %d (setDefaults may not have run)", len(keys))
	}

	root := findModuleRoot(t)
	blob := collectConsumerBlob(t, root)

	var dead []string
	for _, key := range keys {
		if documentedNotHonored[key] {
			continue
		}
		if keyHasConsumer(key, blob) {
			continue
		}
		dead = append(dead, key)
	}

	if len(dead) > 0 {
		t.Errorf("%d config key(s) are parsed but have no consumer outside lib/config and are not documented as \"not yet honored\" (dead knobs — wire them or document them):\n  %s",
			len(dead), strings.Join(dead, "\n  "))
	}
}

// keyHasConsumer reports whether the config key plausibly reaches behavior:
// either the full dotted key string appears in the consumer blob (a subsystem
// reading viper directly), or one of the derived field identifiers appears as a
// whole token.
func keyHasConsumer(key, blob string) bool {
	if strings.Contains(blob, key) {
		return true
	}
	leaf := key
	if i := strings.LastIndex(key, "."); i >= 0 {
		leaf = key[i+1:]
	}
	for _, ident := range fieldIdentifierCandidates(leaf) {
		if tokenPresent(ident, blob) {
			return true
		}
	}
	return false
}

// acronymMap normalizes lowercase key segments to their conventional Go
// identifier casing so the derived field name matches the real struct field.
var acronymMap = map[string]string{
	"ntcp2": "NTCP2", "ssu2": "SSU2", "i2cp": "I2CP", "i2np": "I2NP",
	"routerinfo": "RouterInfo", "leaseset": "LeaseSet", "url": "URL",
	"id": "ID", "tls": "TLS", "http": "HTTP", "https": "HTTPS", "api": "API",
	"nat": "NAT", "upnp": "UPnP", "pmp": "PMP", "kad": "KAD", "dht": "DHT",
	"su3": "SU3", "b32": "B32", "cors": "CORS", "nsr": "NSR", "ttl": "TTL",
	"max": "Max", "ip": "IP", "os": "OS", "netid": "NetID", "net": "Net",
}

// fieldIdentifierCandidates returns the plausible Go field identifiers for a
// snake_case key leaf: one with acronym normalization and one with naive
// per-segment capitalization. The consumer check accepts either.
func fieldIdentifierCandidates(leaf string) []string {
	segs := strings.Split(leaf, "_")
	acronym := strings.Builder{}
	naive := strings.Builder{}
	for _, s := range segs {
		if a, ok := acronymMap[s]; ok {
			acronym.WriteString(a)
		} else if s != "" {
			acronym.WriteString(strings.ToUpper(s[:1]) + s[1:])
		}
		if s != "" {
			naive.WriteString(strings.ToUpper(s[:1]) + s[1:])
		}
	}
	return []string{acronym.String(), naive.String()}
}

// tokenPresent reports whether ident appears in blob as a whole identifier
// (not as a substring of a longer identifier), avoiding false positives like
// "testinterval" matching inside "tunneltestinterval".
func tokenPresent(ident, blob string) bool {
	if ident == "" {
		return false
	}
	// Match ident only when bounded by non-identifier characters (or the padded
	// edges). Go's regexp has no lookaround, so we require an explicit non-ident
	// char on each side and pad the blob to bound edge occurrences.
	re, err := regexp.Compile(`[^A-Za-z0-9_]` + regexp.QuoteMeta(ident) + `[^A-Za-z0-9_]`)
	if err != nil {
		return false
	}
	padded := " " + blob + " "
	return re.MatchString(padded)
}

// findModuleRoot walks up from the test's working directory to the module root
// (the directory containing go.mod).
func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate module root (go.mod) from test working directory")
		}
		dir = parent
	}
}

// collectConsumerBlob concatenates every non-test .go file outside lib/config
// into one string for consumer searching.
func collectConsumerBlob(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // best-effort scan
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		// lib/config only parses/validates config; it is not a consumer.
		if strings.HasPrefix(rel, "lib/config/") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		b.Write(data)
		b.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatalf("walk module root: %v", err)
	}
	return b.String()
}
