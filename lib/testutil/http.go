package testutil

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"
)

// PostJSON sends an HTTP POST with the given JSON body to url and returns the
// raw response bytes. It fails the test on any transport or I/O error.
func PostJSON(t *testing.T, url string, jsonBody []byte) []byte {
	t.Helper()

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	return respBody
}
