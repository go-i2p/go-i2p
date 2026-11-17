package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// derivedRouterFields lists RouterConfig scalar fields that are intentionally
// NOT read from a single viper key in NewRouterConfigFromViper: they are either
// computed from other config (bandwidth-tier auto-derivation) or read through a
// dedicated build* helper rather than a direct viper.Get in the return literal.
// Adding a field here is a deliberate decision that must be justified in a
// comment; the guard otherwise requires every externally-consumed scalar field
// to be populated from a registered viper key.
var derivedRouterFields = map[string]string{
	// BaseDir/WorkingDir are read directly in the literal, so they are NOT here.
	// (No scalar RouterConfig field is currently derived; the map exists so the
	// guard has an explicit, auditable escape hatch.)
}

// TestEveryConsumedRouterFieldIsRegistered is the "unregistered-knob" guard that
// complements TestEveryConfigKeyHasConsumer.
//
// TestEveryConfigKeyHasConsumer enumerates keys registered by setDefaults() and
// asserts each has a consumer. Its blind spot is the opposite class: a
// RouterConfig field that HAS a live consumer outside lib/config but was never
// registered as a viper key (and never read in NewRouterConfigFromViper). Such a
// field is silently always-zero for operators — exactly the always_zero_hop_inbound
// finding, where the field and its router wiring existed but no viper key/flag
// fed it, so config.yaml's always_zero_hop_inbound was ignored.
//
// This test reflects over the runtime RouterConfig's scalar fields, and for each
// one that is referenced outside lib/config (i.e. it reaches behavior), asserts:
//  1. NewRouterConfigFromViper populates it from a viper.Get*("key") call, and
//  2. that key is registered by setDefaults() (so it appears in viper.AllKeys()).
//
// A field that reaches behavior but fails either check is an unregistered knob:
// the operator has no way to set it, and the value the consumer reads is always
// the zero value.
func TestEveryConsumedRouterFieldIsRegistered(t *testing.T) {
	viper.Reset()
	setDefaults()
	registered := map[string]bool{}
	for _, k := range viper.AllKeys() {
		registered[k] = true
	}

	root := findModuleRoot(t)
	blob := collectConsumerBlob(t, root)

	// Map each RouterConfig scalar field to the viper key NewRouterConfigFromViper
	// reads it from (empty when the field is not read from viper at all).
	fieldToKey := routerFieldViperKeys(t, root)

	rt := reflect.TypeOf(RouterConfig{})
	var unregistered []string
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !isScalarConfigField(f.Type) {
			continue // nested sections are built by their own build* helpers
		}
		// Only fields that actually reach behavior outside lib/config matter;
		// an unconsumed field is the OTHER guard's problem (dead knob), not this one.
		if !fieldHasExternalConsumer(f.Name, blob) {
			continue
		}
		key, read := fieldToKey[f.Name]
		switch {
		case !read:
			if _, ok := derivedRouterFields[f.Name]; ok {
				continue
			}
			unregistered = append(unregistered,
				f.Name+" (consumed outside lib/config but never read from viper in NewRouterConfigFromViper)")
		case !registered[key]:
			unregistered = append(unregistered,
				f.Name+" (read from viper key \""+key+"\" which setDefaults() never registers)")
		}
	}

	if len(unregistered) > 0 {
		t.Errorf("%d RouterConfig field(s) reach behavior but are not settable by an operator (unregistered knobs — register a viper key in setDefaults() and read it in NewRouterConfigFromViper):\n  %s",
			len(unregistered), strings.Join(unregistered, "\n  "))
	}
}

// isScalarConfigField reports whether t is a scalar (operator-settable leaf)
// config field. Nested sections (pointers, structs, slices, maps) are built by
// their own build* helpers and covered by their own guards.
func isScalarConfigField(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.String,
		reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	default:
		// time.Duration is an int64 kind and is already caught above.
		return false
	}
}

// fieldHasExternalConsumer reports whether the field identifier appears as a
// whole token in the consumer blob (every non-test .go file outside lib/config).
// This mirrors keyHasConsumer's token matching so the two guards agree on what
// "reaches behavior" means.
func fieldHasExternalConsumer(name, blob string) bool {
	return tokenPresent(name, blob)
}

// routerFieldViperKeys parses lib/config/config.go and returns a map from each
// RouterConfig field name to the viper key NewRouterConfigFromViper reads it
// from. Fields assigned from a build* helper (nested sections) or a computed
// expression are absent from the map.
func routerFieldViperKeys(t *testing.T, root string) map[string]string {
	t.Helper()
	path := filepath.Join(root, "lib", "config", "config.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	out := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != "NewRouterConfigFromViper" {
			return true
		}
		// Find the returned composite literal and record Field: viper.Get*("key").
		ast.Inspect(fn, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if !isRouterConfigType(lit.Type) {
				return true
			}
			for _, e := range lit.Elts {
				kv, ok := e.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				id, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if key := viperKeyFromExpr(kv.Value); key != "" {
					out[id.Name] = key
				}
			}
			return true
		})
		return true
	})

	// Sanity: the map must be non-empty and include a known key, otherwise the
	// parse/regex approach silently matched nothing and the guard would pass vacuously.
	if len(out) < 10 {
		t.Fatalf("expected many viper-backed RouterConfig fields, got %d (NewRouterConfigFromViper parse may have failed)", len(out))
	}
	if _, ok := out["Hidden"]; !ok {
		t.Fatal("expected Hidden to be read from viper in NewRouterConfigFromViper")
	}
	return out
}

// isRouterConfigType reports whether e refers to the RouterConfig type. Within
// this package the literal is written as &RouterConfig{...}, so e is an
// *ast.Ident; a qualified reference (pkg.RouterConfig) is also accepted.
func isRouterConfigType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == "RouterConfig"
	case *ast.SelectorExpr:
		return t.Sel != nil && t.Sel.Name == "RouterConfig"
	default:
		return false
	}
}

// viperKeyFromExpr returns the string key argument of a viper.Get*("key") call
// expression, or "" if expr is not such a call.
func viperKeyFromExpr(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || !strings.HasPrefix(sel.Sel.Name, "Get") {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "viper" {
		return ""
	}
	if len(call.Args) != 1 {
		return ""
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	key, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return key
}
