package transport

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireInterfaceMethod asserts that iface has a method named name with
// the given number of input and output parameters, and returns the method.
func requireInterfaceMethod(t *testing.T, iface reflect.Type, name string, numIn, numOut int) reflect.Method {
	t.Helper()
	m, found := iface.MethodByName(name)
	require.True(t, found, "%s method must exist", name)
	assert.Equal(t, numIn, m.Type.NumIn(), "%s should take %d argument(s)", name, numIn)
	assert.Equal(t, numOut, m.Type.NumOut(), "%s should return %d value(s)", name, numOut)
	return m
}
