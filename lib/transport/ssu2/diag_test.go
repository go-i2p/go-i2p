package ssu2

// diag_test.go – Diagnostic test to isolate exactly where data-phase packets
// fail in the go-noise pipeline.

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/require"
)

func TestDiag_DataPhaseTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverConn, clientConn := loopbackPair(t, ctx)
	defer serverConn.Close()
	defer clientConn.Close()

	// Pre-send stats
	serverBefore := serverConn.RecvStats()
	t.Logf("server recv stats before send: %+v", serverBefore)
	clientBefore := clientConn.RecvStats()
	t.Logf("client recv stats before send: %+v", clientBefore)

	// Create a simple I2NP message block (type 10 = DeliveryStatus)
	// Format: I2NP type(1) + messageID(4) + shortExpiration(4) + body
	block := &ssu2noise.SSU2Block{
		Type: ssu2noise.BlockTypeI2NPMessage,
		Data: []byte{10, 0, 0, 0, 1, 0, 0, 0, 0, 'h', 'e', 'l', 'l', 'o'},
	}

	t.Log("writing block from client to server...")
	err := clientConn.WriteBlocks([]*ssu2noise.SSU2Block{block})
	require.NoError(t, err, "WriteBlocks")
	t.Log("WriteBlocks succeeded")

	// Give the recvLoop time to process the packet
	time.Sleep(1 * time.Second)

	// Check recv stats on server to see if packets arrived / parsed / decrypted
	serverAfter := serverConn.RecvStats()
	t.Logf("server recv stats after send: %+v", serverAfter)

	// Try to read
	serverConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65536)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Logf("server Read err: %v", err)
	} else {
		t.Logf("server Read got %d bytes: %x", n, buf[:n])
	}

	t.Logf("=== FINAL server recv stats: %+v", serverConn.RecvStats())
}

func TestDiag_FragmentedTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverConn, clientConn := loopbackPair(t, ctx)
	defer serverConn.Close()
	defer clientConn.Close()

	// Create a large message that will be fragmented
	largePayload := make([]byte, 3000)
	_, err := rand.Read(largePayload)
	require.NoError(t, err)

	msg := newTestI2NPMessage(largePayload)
	blocks, err := FragmentI2NPMessage(msg, maxSSU2PayloadIPv4)
	require.NoError(t, err)
	t.Logf("fragmented into %d blocks:", len(blocks))
	for i, b := range blocks {
		t.Logf("  block[%d]: type=%d, len=%d", i, b.Type, len(b.Data))
	}

	// Send blocks
	t.Log("writing fragmented blocks...")
	err = clientConn.WriteBlocks(blocks)
	require.NoError(t, err, "WriteBlocks")
	t.Log("WriteBlocks succeeded")

	// Wait and check stats
	time.Sleep(2 * time.Second)
	serverStats := serverConn.RecvStats()
	clientStats := clientConn.RecvStats()
	t.Logf("server recv stats: %+v", serverStats)
	t.Logf("client recv stats: %+v", clientStats)

	// Try to read
	serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65536)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Logf("server Read err: %v", err)
	} else {
		t.Logf("server Read got %d bytes", n)
	}

	// Also try direct I2NP send (via conn.Write, bypassing session)
	t.Log("--- Testing I2NP via session layer ---")
	l := newTestLogger("diag_frag")
	serverSess := NewSSU2Session(serverConn, ctx, l)
	clientSess := NewSSU2Session(clientConn, ctx, l)
	defer serverSess.Close()
	defer clientSess.Close()

	// Send a small message first through session
	small := newTestI2NPMessage([]byte("small test"))
	t.Log("sending small message through session...")
	err = clientSess.QueueSendI2NP(small)
	t.Logf("QueueSendI2NP(small) err: %v", err)

	t.Log("reading small message...")
	_, err = serverSess.ReadNextI2NP()
	t.Logf("ReadNextI2NP(small) err: %v", err)

	// Now try the large message through session
	msg2 := &i2np.BaseI2NPMessage{}
	*msg2 = *msg
	t.Log("sending large message through session...")
	err = clientSess.QueueSendI2NP(msg2)
	t.Logf("QueueSendI2NP(large) err: %v", err)

	t.Log("reading large message...")
	_, err = serverSess.ReadNextI2NP()
	t.Logf("ReadNextI2NP(large) err: %v", err)
}
