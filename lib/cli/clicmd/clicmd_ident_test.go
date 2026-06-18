package clicmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestExecuteI2PControlIdent(t *testing.T) {
	const expectedPassword = "testpassword"
	const expectedToken = "test-token"
	const expectedHash = "dGVzdC1yb3V0ZXItaGFzaA=="

	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST request, got %s", r.Method)
		}

		defer r.Body.Close()
		var req struct {
			JSONRPC string                 `json:"jsonrpc"`
			Method  string                 `json:"method"`
			Params  map[string]interface{} `json:"params"`
			ID      interface{}            `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}

		result := map[string]interface{}{}
		switch req.Method {
		case "Authenticate":
			if req.Params["Password"] != expectedPassword {
				t.Fatalf("unexpected Authenticate password: %v", req.Params["Password"])
			}
			result["API"] = float64(1)
			result["Token"] = expectedToken
		case "RouterInfo":
			if req.Params["Token"] != expectedToken {
				t.Fatalf("unexpected RouterInfo token: %v", req.Params["Token"])
			}
			if _, ok := req.Params["i2p.router.hash"]; !ok {
				t.Fatalf("RouterInfo missing i2p.router.hash request field")
			}
			result["i2p.router.hash"] = expectedHash
		default:
			t.Fatalf("unexpected method %q", req.Method)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  result,
		})
	}))
	defer rpcServer.Close()

	oldHost, oldPort, oldPath, oldPassword := host, port, path, password
	oldVerbose, oldBlock, oldParseAddr := verbose, block, parseAddr
	host = ""
	port = ""
	path = "jsonrpc"
	password = ""
	verbose = false
	block = false
	parseAddr = false
	t.Cleanup(func() {
		host = oldHost
		port = oldPort
		path = oldPath
		password = oldPassword
		verbose = oldVerbose
		block = oldBlock
		parseAddr = oldParseAddr
		viper.Reset()
	})

	target, err := normalizeTestAddress(rpcServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to normalize test address: %v", err)
	}
	viper.Set("i2pcontrol.address", target)
	viper.Set("i2pcontrol.password", expectedPassword)

	output, err := captureStdout(func() error {
		return executeI2PControl(nil, []string{"ident"})
	})
	if err != nil {
		t.Fatalf("executeI2PControl(ident) returned error: %v", err)
	}

	if strings.TrimSpace(output) != expectedHash {
		t.Fatalf("unexpected ident output: got %q want %q", strings.TrimSpace(output), expectedHash)
	}
}

func captureStdout(fn func() error) (string, error) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w

	runErr := fn()
	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, readErr := io.Copy(&buf, r)
	_ = r.Close()
	if readErr != nil {
		return "", readErr
	}

	return buf.String(), runErr
}

func normalizeTestAddress(addr string) (string, error) {
	hostPart, portPart, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if hostPart == "::" || hostPart == "0.0.0.0" {
		hostPart = "127.0.0.1"
	}
	return net.JoinHostPort(hostPart, portPart), nil
}
