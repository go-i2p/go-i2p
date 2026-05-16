package i2np

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestParseECIESGarlicClove_LocalShortTunnelBuildReply(t *testing.T) {
	expiry := time.Unix(1770000000, 0).UTC()
	payload := append([]byte{1}, bytes.Repeat([]byte{0xaa}, 218)...)
	messageID := uint32(0x10203040)

	data := make([]byte, 1+ShortI2NPHeaderSize+len(payload))
	data[0] = 0x00
	data[1] = byte(I2NPMessageTypeShortTunnelBuildReply)
	binary.BigEndian.PutUint32(data[2:6], messageID)
	binary.BigEndian.PutUint32(data[6:10], uint32(expiry.Unix()))
	copy(data[10:], payload)

	garlic, err := parseECIESGarlicClove(data)
	if err != nil {
		t.Fatalf("parseECIESGarlicClove returned error: %v", err)
	}

	if garlic.Count != 1 {
		t.Fatalf("expected 1 clove, got %d", garlic.Count)
	}
	if len(garlic.Cloves) != 1 {
		t.Fatalf("expected 1 parsed clove, got %d", len(garlic.Cloves))
	}

	clove := garlic.Cloves[0]
	if clove.DeliveryInstructions.Flag != 0x00 {
		t.Fatalf("expected LOCAL delivery flag 0x00, got 0x%02x", clove.DeliveryInstructions.Flag)
	}
	if clove.Message.Type() != I2NPMessageTypeShortTunnelBuildReply {
		t.Fatalf("expected wrapped type %d, got %d", I2NPMessageTypeShortTunnelBuildReply, clove.Message.Type())
	}
	if clove.Message.MessageID() != int(messageID) {
		t.Fatalf("expected message ID %d, got %d", messageID, clove.Message.MessageID())
	}
	if !clove.Message.Expiration().Equal(expiry) {
		t.Fatalf("expected expiration %v, got %v", expiry, clove.Message.Expiration())
	}

	carrier, ok := clove.Message.(DataCarrier)
	if !ok {
		t.Fatal("parsed I2NP message does not implement DataCarrier")
	}
	if !bytes.Equal(carrier.GetData(), payload) {
		t.Fatalf("expected payload %x, got %x", payload[:8], carrier.GetData()[:8])
	}

	if garlic.MessageID != int(messageID) {
		t.Fatalf("expected garlic message ID %d, got %d", messageID, garlic.MessageID)
	}
	if !garlic.Expiration.Equal(expiry) {
		t.Fatalf("expected garlic expiration %v, got %v", expiry, garlic.Expiration)
	}
}
