package netdb

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/i2np"
)

// Compile-time regression guard: StdNetDB must satisfy source-aware storage
// so DatabaseStore ingress can preserve source attribution for admission fairness.
var _ i2np.NetDBStoreWithSource = (*StdNetDB)(nil)

func TestStdNetDB_ImplementsSourceAwareStorePath(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	db.Stop()

	if _, ok := any(db).(i2np.NetDBStoreWithSource); !ok {
		t.Fatal("StdNetDB must implement i2np.NetDBStoreWithSource")
	}
}
