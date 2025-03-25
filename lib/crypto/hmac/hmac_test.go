package hmac

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// XXX: IMPLEMENT THIS
func Test_I2PHMAC(t *testing.T) {
	data := make([]byte, 64)
	for idx := range data {
		data[idx] = 1
	}
	var k HMACKey
	for idx := range k[:] {
		k[idx] = 1
	}
	d := I2PHMAC(data, k)
	expected_str := "WypV9tIaH1Kn9i7/9OqP6Q=="
	expected, _ := base64.StdEncoding.DecodeString(expected_str)
	if !bytes.Equal(d[:], expected) {
		t.Logf("%d vs %d", len(d), len(expected))
		t.Logf("%q != %q", d, expected)
		t.Fail()
	}
}
