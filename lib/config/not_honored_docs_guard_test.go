package config

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestNotHonoredDocsMatchAllowlist guards against the drift that occurred when
// several knobs were wired to behavior but config.yaml.example still carried a
// stale "not yet honored" note (and, conversely, when a newly-dead knob was
// wired into the allowlist but not annotated in the example file).
//
// It parses config.yaml.example, collects every key that is annotated as
// "not yet honored" (either directly, or by a "see ... note above" reference),
// and asserts that set is EXACTLY the documentedNotHonored allowlist used by
// TestEveryConfigKeyHasConsumer. If a knob is wired, its note must be removed;
// if a knob is intentionally inert, it must appear in both places.
func TestNotHonoredDocsMatchAllowlist(t *testing.T) {
	root := findModuleRoot(t)
	examplePath := filepath.Join(root, "config.yaml.example")

	annotated, err := collectNotHonoredKeys(examplePath)
	if err != nil {
		t.Fatalf("reading %s: %v", examplePath, err)
	}

	// Compare the two sets.
	allow := make(map[string]bool, len(documentedNotHonored))
	for k := range documentedNotHonored {
		allow[k] = true
	}

	var onlyInDocs, onlyInAllow []string
	for k := range annotated {
		if !allow[k] {
			onlyInDocs = append(onlyInDocs, k)
		}
	}
	for k := range allow {
		if !annotated[k] {
			onlyInAllow = append(onlyInAllow, k)
		}
	}
	sort.Strings(onlyInDocs)
	sort.Strings(onlyInAllow)

	if len(onlyInDocs) > 0 {
		t.Errorf("config.yaml.example annotates %d key(s) as \"not yet honored\" that are NOT in documentedNotHonored — either the knob is wired (remove the stale note) or it is genuinely dead (add it to documentedNotHonored):\n  %s",
			len(onlyInDocs), strings.Join(onlyInDocs, "\n  "))
	}
	if len(onlyInAllow) > 0 {
		t.Errorf("documentedNotHonored lists %d key(s) that config.yaml.example does NOT annotate as \"not yet honored\" — add the note to the example file:\n  %s",
			len(onlyInAllow), strings.Join(onlyInAllow, "\n  "))
	}
}

var (
	// topLevelKeyRe matches a column-0 YAML mapping key (a section header).
	topLevelKeyRe = regexp.MustCompile(`^([a-z0-9_]+):\s*(#.*)?$`)
	// nestedKeyRe matches an indented YAML mapping key.
	nestedKeyRe = regexp.MustCompile(`^\s+([a-z0-9_]+):`)
)

// collectNotHonoredKeys returns the set of fully-qualified (section.key) config
// keys that config.yaml.example annotates as "not yet honored". A key is
// annotated when its immediately-preceding comment block contains "not yet
// honored", or a "note above" back-reference (used when one note covers several
// adjacent keys).
func collectNotHonoredKeys(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]bool)
	section := ""
	var commentBuf []string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		// Comment line: accumulate for the next key.
		if strings.HasPrefix(trimmed, "#") {
			commentBuf = append(commentBuf, trimmed)
			continue
		}

		// Blank line: keep the buffer (notes sometimes sit above a blank gap),
		// but do not treat it as a key.
		if trimmed == "" {
			continue
		}

		// Section header at column 0.
		if m := topLevelKeyRe.FindStringSubmatch(line); m != nil {
			section = m[1]
			commentBuf = nil
			continue
		}

		// Nested key.
		if m := nestedKeyRe.FindStringSubmatch(line); m != nil {
			key := m[1]
			blob := strings.Join(commentBuf, " ")
			if strings.Contains(blob, "not yet honored") || strings.Contains(blob, "note above") {
				if section != "" {
					result[section+"."+key] = true
				}
			}
			commentBuf = nil
			continue
		}

		// Any other line (list item, etc.) resets the buffer.
		commentBuf = nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
