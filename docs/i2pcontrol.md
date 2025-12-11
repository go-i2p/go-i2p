# I2PControl JSON-RPC Server User Guide

## Introduction

I2PControl is a JSON-RPC 2.0 interface for monitoring I2P routers. This guide explains how to enable, configure, and use the I2PControl server in go-i2p for development and testing purposes.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Configuration](#configuration)
3. [Using the API](#using-the-api)
4. [Security](#security)
5. [Troubleshooting](#troubleshooting)
6. [Advanced Topics](#advanced-topics)

---

## Quick Start

### Step 1: Enable I2PControl

Edit your `config.yaml`:

```yaml
i2pcontrol:
  enabled: true
  address: "localhost:7650"
  password: "your-secure-password"
```

Or use command-line flags:

```bash
./go-i2p --i2pcontrol.enabled=true --i2pcontrol.password="your-password"
```

### Step 2: Start the Router

```bash
./go-i2p --config config.yaml
```

Look for the startup message in logs:

```
INFO[0000] starting I2PControl server                    address="localhost:7650" at=router.startI2PControlServer
```

### Step 3: Test Connectivity

```bash
# Authenticate to get a token
curl -X POST http://localhost:7650/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "Authenticate",
    "params": {
      "API": 1,
      "Password": "your-secure-password"
    }
  }'
```

Expected response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "API": 1,
    "Token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

Save the token for subsequent requests.

---

## Configuration

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable I2PControl server |
| `address` | string | `"localhost:7650"` | Listen address (host:port) |
| `password` | string | `"itoopie"` | Authentication password |
| `use_https` | bool | `false` | Enable HTTPS/TLS |
| `cert_file` | string | `""` | TLS certificate path |
| `key_file` | string | `""` | TLS private key path |
| `token_expiration` | duration | `10m` | Token validity duration |

### Configuration Methods

#### 1. Configuration File (Recommended)

Create or edit `config.yaml`:

```yaml
# I2PControl Configuration
i2pcontrol:
  # Enable the RPC server
  enabled: true
  
  # Listen address
  # Use "localhost:7650" for local-only access (recommended)
  # Use "0.0.0.0:7650" for network access (requires HTTPS!)
  address: "localhost:7650"
  
  # Authentication password
  # IMPORTANT: Change from default in production!
  password: "change-me-in-production"
  
  # HTTPS/TLS settings
  use_https: false
  # cert_file: "/path/to/cert.pem"
  # key_file: "/path/to/key.pem"
  
  # Token expiration (examples: 5m, 15m, 1h)
  token_expiration: 10m
```

#### 2. Command-Line Flags

Override configuration with flags:

```bash
./go-i2p \
  --i2pcontrol.enabled=true \
  --i2pcontrol.address="localhost:7650" \
  --i2pcontrol.password="my-password"
```

#### 3. Environment Variables

Set via Viper environment variables:

```bash
export I2PCONTROL_ENABLED=true
export I2PCONTROL_ADDRESS=localhost:7650
export I2PCONTROL_PASSWORD=my-password
./go-i2p
```

### Configuration Validation

The server validates configuration on startup:

- **Password required**: Cannot be empty
- **HTTPS requirements**: If `use_https` is true, both `cert_file` and `key_file` must be specified
- **Port availability**: Specified port must not be in use

Validation errors appear in logs:

```
ERRO[0000] failed to start I2PControl server             error="password cannot be empty"
```

---

## Using the API

### Authentication Flow

All RPC methods (except `Authenticate`) require a valid authentication token.

**Step 1: Authenticate**

```bash
curl -X POST http://localhost:7650/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "Authenticate",
    "params": {
      "API": 1,
      "Password": "your-password"
    }
  }'
```

**Step 2: Extract Token**

Using `jq`:

```bash
TOKEN=$(curl -s -X POST http://localhost:7650/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "Authenticate",
    "params": {"API": 1, "Password": "your-password"}
  }' | jq -r '.result.Token')

echo "Token: $TOKEN"
```

**Step 3: Use Token**

Include token in all subsequent requests:

```bash
curl -X POST http://localhost:7650/jsonrpc \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 2,
    \"method\": \"Echo\",
    \"params\": {
      \"Token\": \"$TOKEN\",
      \"Echo\": \"test\"
    }
  }"
```

### Available Methods

#### Echo - Connection Test

Test RPC connectivity by echoing a value.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "Echo",
  "params": {
    "Token": "your-token-here",
    "Echo": "hello world"
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "Result": "hello world"
  }
}
```

**curl Example:**

```bash
curl -X POST http://localhost:7650/jsonrpc \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 2,
    \"method\": \"Echo\",
    \"params\": {
      \"Token\": \"$TOKEN\",
      \"Echo\": \"test\"
    }
  }" | jq .
```

#### GetRate - Bandwidth Statistics

Query current bandwidth rates.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "GetRate",
  "params": {
    "Token": "your-token-here",
    "i2p.router.net.bw.inbound.15s": null,
    "i2p.router.net.bw.outbound.15s": null
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "i2p.router.net.bw.inbound.15s": 12345.67,
    "i2p.router.net.bw.outbound.15s": 23456.78
  }
}
```

**curl Example:**

```bash
curl -X POST http://localhost:7650/jsonrpc \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 3,
    \"method\": \"GetRate\",
    \"params\": {
      \"Token\": \"$TOKEN\",
      \"i2p.router.net.bw.inbound.15s\": null,
      \"i2p.router.net.bw.outbound.15s\": null
    }
  }" | jq .
```

**Supported Rate Metrics:**

- `i2p.router.net.bw.inbound.15s` - Inbound bandwidth (bytes/sec, 15s average)
- `i2p.router.net.bw.outbound.15s` - Outbound bandwidth (bytes/sec, 15s average)

#### RouterInfo - Router Status

Query router operational status and statistics.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "RouterInfo",
  "params": {
    "Token": "your-token-here",
    "i2p.router.uptime": null,
    "i2p.router.version": null,
    "i2p.router.net.tunnels.participating": null,
    "i2p.router.netdb.knownpeers": null
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "i2p.router.uptime": 3600000,
    "i2p.router.version": "0.1.0-go",
    "i2p.router.net.tunnels.participating": 10,
    "i2p.router.netdb.knownpeers": 150
  }
}
```

**curl Example:**

```bash
curl -X POST http://localhost:7650/jsonrpc \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 4,
    \"method\": \"RouterInfo\",
    \"params\": {
      \"Token\": \"$TOKEN\",
      \"i2p.router.uptime\": null,
      \"i2p.router.version\": null,
      \"i2p.router.net.tunnels.participating\": null,
      \"i2p.router.netdb.knownpeers\": null
    }
  }" | jq .
```

**Supported RouterInfo Metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `i2p.router.uptime` | int64 | Router uptime in milliseconds |
| `i2p.router.version` | string | Router version string |
| `i2p.router.net.tunnels.participating` | int | Number of tunnels we're participating in |
| `i2p.router.netdb.knownpeers` | int | Number of known routers in NetDB |
| `i2p.router.netdb.activepeers` | int | Number of currently active peers |
| `i2p.router.netdb.fastpeers` | int | Number of fast peers |

### Error Handling

All errors follow JSON-RPC 2.0 error format:

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "error": {
    "code": -32000,
    "message": "authentication required"
  }
}
```

**Common Error Codes:**

| Code | Name | Common Causes |
|------|------|---------------|
| -32700 | Parse error | Invalid JSON syntax |
| -32600 | Invalid Request | Missing required fields (jsonrpc, method, params) |
| -32601 | Method not found | Typo in method name |
| -32602 | Invalid params | Wrong parameter format |
| -32603 | Internal error | Server-side problem |
| -32000 | Auth required | Missing or expired token |
| -32001 | Auth failed | Wrong password |

### Complete Example Script

```bash
#!/bin/bash
# test-i2pcontrol.sh - Test I2PControl API

API_URL="http://localhost:7650/jsonrpc"
PASSWORD="your-password"

echo "=== Authenticating ==="
AUTH_RESPONSE=$(curl -s -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 1,
    \"method\": \"Authenticate\",
    \"params\": {
      \"API\": 1,
      \"Password\": \"$PASSWORD\"
    }
  }")

echo "$AUTH_RESPONSE" | jq .

TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.result.Token')

if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
  echo "Authentication failed!"
  exit 1
fi

echo -e "\n=== Echo Test ==="
curl -s -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 2,
    \"method\": \"Echo\",
    \"params\": {
      \"Token\": \"$TOKEN\",
      \"Echo\": \"Hello I2P!\"
    }
  }" | jq .

echo -e "\n=== Router Info ==="
curl -s -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 3,
    \"method\": \"RouterInfo\",
    \"params\": {
      \"Token\": \"$TOKEN\",
      \"i2p.router.uptime\": null,
      \"i2p.router.version\": null,
      \"i2p.router.net.tunnels.participating\": null,
      \"i2p.router.netdb.knownpeers\": null
    }
  }" | jq .

echo -e "\n=== Bandwidth Stats ==="
curl -s -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 4,
    \"method\": \"GetRate\",
    \"params\": {
      \"Token\": \"$TOKEN\",
      \"i2p.router.net.bw.inbound.15s\": null,
      \"i2p.router.net.bw.outbound.15s\": null
    }
  }" | jq .

echo -e "\n=== Tests Complete ==="
```

Save as `test-i2pcontrol.sh`, make executable, and run:

```bash
chmod +x test-i2pcontrol.sh
./test-i2pcontrol.sh
```

---

## Security

### Development vs. Production

**This implementation is designed for development use.** For production deployments, implement additional security measures.

### Threat Model

**What's Protected:**
- Token forgery (HMAC-SHA256 signing)
- Unauthorized method calls (token validation)
- Method enumeration (authentication required first)

**What's NOT Protected:**
- Password sniffing (use HTTPS!)
- Token replay attacks (within validity period)
- Denial of service (no rate limiting)
- Brute force attacks (no account lockout)
- Man-in-the-middle (use HTTPS!)

### Best Practices

#### 1. Change Default Password

**Never use the default password in production!**

```yaml
i2pcontrol:
  password: "change-me-in-production"  # ❌ BAD
  password: "Xk9#mP2$vL8@qR4!"         # ✅ GOOD
```

Generate strong passwords:

```bash
# Linux/Mac
openssl rand -base64 32

# Or use a password manager
```

#### 2. Enable HTTPS for Network Access

**Never expose HTTP I2PControl to the network!**

```yaml
i2pcontrol:
  address: "0.0.0.0:7650"  # Accessible from network
  use_https: true          # REQUIRED
  cert_file: "/etc/ssl/certs/i2pcontrol-cert.pem"
  key_file: "/etc/ssl/private/i2pcontrol-key.pem"
```

Generate self-signed certificate (testing only):

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout i2pcontrol-key.pem \
  -out i2pcontrol-cert.pem \
  -days 365 -nodes \
  -subj "/CN=localhost"
```

For production, use certificates from a trusted CA:

```bash
# Let's Encrypt example
certbot certonly --standalone -d your-domain.com

# Update config to use Let's Encrypt certs
cert_file: "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
key_file: "/etc/letsencrypt/live/your-domain.com/privkey.pem"
```

#### 3. Limit Network Exposure

**Localhost only (recommended for development):**

```yaml
i2pcontrol:
  address: "localhost:7650"  # Only accessible from local machine
```

**Specific interface:**

```yaml
i2pcontrol:
  address: "192.168.1.100:7650"  # Only accessible from this interface
```

**All interfaces with firewall:**

```yaml
i2pcontrol:
  address: "0.0.0.0:7650"
  use_https: true
```

Then configure firewall (iptables example):

```bash
# Allow only from specific IP
iptables -A INPUT -p tcp --dport 7650 -s 192.168.1.50 -j ACCEPT
iptables -A INPUT -p tcp --dport 7650 -j DROP
```

#### 4. Token Expiration

Shorter token lifetimes improve security but reduce convenience:

```yaml
i2pcontrol:
  token_expiration: 5m   # High security (frequent re-auth)
  token_expiration: 10m  # Balanced (default)
  token_expiration: 30m  # Low security (convenient)
```

#### 5. Monitor Access

Check logs for suspicious activity:

```bash
# grep for authentication failures
grep "authentication failed" router.log

# grep for invalid tokens
grep "authentication required" router.log
```

Consider implementing:
- Failed authentication tracking
- Rate limiting per IP
- Audit logging of all RPC calls

### Security Checklist

**For Development (localhost only):**
- [x] Bind to `localhost` only
- [ ] Change default password (recommended)
- [ ] HTTPS not required for localhost

**For Production (network access):**
- [ ] Changed default password to strong password
- [ ] HTTPS enabled with valid certificates
- [ ] Firewall rules configured
- [ ] Token expiration set appropriately
- [ ] Regular security updates
- [ ] Audit logging enabled (future enhancement)

---

## Troubleshooting

### Server Won't Start

#### Problem: "bind: address already in use"

**Cause:** Port 7650 is already in use by another process.

**Solution 1:** Stop the conflicting process:

```bash
# Find process using port 7650
lsof -i :7650
# or
netstat -tulpn | grep 7650

# Kill the process
kill <PID>
```

**Solution 2:** Use a different port:

```yaml
i2pcontrol:
  address: "localhost:7651"
```

#### Problem: "failed to start I2PControl server: password cannot be empty"

**Cause:** Password is not configured.

**Solution:** Set password in configuration:

```yaml
i2pcontrol:
  enabled: true
  password: "your-password"
```

#### Problem: "certificate signed by unknown authority" (HTTPS)

**Cause:** Using self-signed certificate.

**Solution 1:** Accept self-signed cert in curl:

```bash
curl -k -X POST https://localhost:7650/jsonrpc ...
```

**Solution 2:** Use certificate from trusted CA (production).

### Authentication Issues

#### Problem: "authentication failed"

**Cause:** Wrong password.

**Solution:** Verify password in config:

```bash
# Check configured password
grep -A 2 "i2pcontrol:" config.yaml | grep password

# Test with correct password
curl -X POST http://localhost:7650/jsonrpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"Authenticate","params":{"API":1,"Password":"<actual-password>"}}'
```

#### Problem: "authentication required" (with token)

**Cause 1:** Token expired.

**Solution:** Re-authenticate to get new token:

```bash
TOKEN=$(curl -s -X POST http://localhost:7650/jsonrpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"Authenticate","params":{"API":1,"Password":"your-password"}}' \
  | jq -r '.result.Token')
```

**Cause 2:** Invalid token format.

**Solution:** Ensure token is included correctly in params:

```json
{
  "params": {
    "Token": "your-token-here",  // ✅ Correct
    ...
  }
}
```

### Connection Issues

#### Problem: "Connection refused"

**Cause 1:** Server not running.

**Solution:** Verify server is enabled and started:

```bash
# Check configuration
grep -A 2 "i2pcontrol:" config.yaml

# Check logs for startup message
grep "I2PControl" router.log
```

**Cause 2:** Wrong address.

**Solution:** Verify listen address:

```bash
# Check what address is bound
netstat -tulpn | grep 7650

# If bound to 127.0.0.1, only localhost works
curl http://localhost:7650/jsonrpc  # ✅ Works
curl http://192.168.1.100:7650/jsonrpc  # ❌ Fails
```

#### Problem: "No route to host" (remote access)

**Cause:** Firewall blocking connection.

**Solution:** Check firewall rules:

```bash
# Linux - check iptables
iptables -L -n | grep 7650

# Temporarily allow (testing only!)
iptables -A INPUT -p tcp --dport 7650 -j ACCEPT
```

### API Issues

#### Problem: "Method not found"

**Cause:** Typo in method name or unsupported method.

**Solution:** Verify method name:

```bash
# Supported methods: Authenticate, Echo, GetRate, RouterInfo
curl -X POST http://localhost:7650/jsonrpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"Echo","params":{"Token":"...","Echo":"test"}}'
#                                           ^^^^^
#                                           Correct capitalization
```

#### Problem: "Invalid params"

**Cause:** Wrong parameter format or missing required fields.

**Solution:** Check parameter structure:

```json
// Echo requires Token and Echo fields
{
  "params": {
    "Token": "your-token",  // ✅ Required
    "Echo": "value"         // ✅ Required
  }
}

// RouterInfo requires Token and requested metrics
{
  "params": {
    "Token": "your-token",              // ✅ Required
    "i2p.router.uptime": null,          // ✅ Set to null to request
    "i2p.router.version": null
  }
}
```

### Performance Issues

#### Problem: Slow response times

**Cause:** Router under heavy load.

**Solution:** Check router performance:

```bash
# Check router CPU usage
top -p $(pgrep go-i2p)

# Check memory usage
ps aux | grep go-i2p
```

#### Problem: Connection timeouts

**Cause:** Network latency or server overload.

**Solution:** Increase client timeout:

```bash
# curl with 30-second timeout
curl --max-time 30 -X POST http://localhost:7650/jsonrpc ...
```

### Debug Logging

Enable verbose logging for troubleshooting:

```yaml
# config.yaml
log:
  level: debug
```

Then check logs:

```bash
# Watch logs in real-time
tail -f router.log | grep i2pcontrol

# Search for errors
grep "ERROR.*i2pcontrol" router.log
```

---

## Advanced Topics

### Token Management

#### Token Lifecycle

1. **Generation:** Created during `Authenticate` call
2. **Validation:** Checked on every RPC method call
3. **Expiration:** Invalid after configured duration
4. **Cleanup:** Expired tokens removed periodically

#### Token Format

Tokens use HMAC-SHA256 signing:

```
token = hex(HMAC-SHA256(password || timestamp, secret))
```

**Security properties:**
- Cryptographically signed (cannot be forged)
- Time-bound (expires after configured duration)
- Verifiable (server validates signature)

#### Token Storage

**Client-side:** Store token securely:

```bash
# Save to file with restricted permissions
TOKEN=$(curl ... | jq -r '.result.Token')
echo "$TOKEN" > .i2pcontrol-token
chmod 600 .i2pcontrol-token

# Use in scripts
TOKEN=$(cat .i2pcontrol-token)
```

**Server-side:** Tokens stored in memory only (lost on restart).

### Programmatic Access

#### Python Example

```python
import requests
import json

class I2PControl:
    def __init__(self, url, password):
        self.url = url
        self.password = password
        self.token = None
        self.request_id = 0
    
    def _call(self, method, params):
        self.request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        }
        response = requests.post(self.url, json=payload)
        result = response.json()
        
        if "error" in result:
            raise Exception(f"RPC Error: {result['error']}")
        
        return result["result"]
    
    def authenticate(self):
        result = self._call("Authenticate", {
            "API": 1,
            "Password": self.password
        })
        self.token = result["Token"]
        return self.token
    
    def echo(self, value):
        return self._call("Echo", {
            "Token": self.token,
            "Echo": value
        })
    
    def get_router_info(self, *metrics):
        params = {"Token": self.token}
        for metric in metrics:
            params[metric] = None
        return self._call("RouterInfo", params)

# Usage
client = I2PControl("http://localhost:7650/jsonrpc", "my-password")
client.authenticate()

print(client.echo("test"))

info = client.get_router_info(
    "i2p.router.uptime",
    "i2p.router.version",
    "i2p.router.netdb.knownpeers"
)
print(json.dumps(info, indent=2))
```

#### Go Example

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type RPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type I2PControlClient struct {
	URL       string
	Password  string
	Token     string
	requestID int
}

func (c *I2PControlClient) call(method string, params interface{}) (json.RawMessage, error) {
	c.requestID++
	req := RPCRequest{
		JSONRPC: "2.0",
		ID:      c.requestID,
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(c.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rpcResp RPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, err
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

func (c *I2PControlClient) Authenticate() error {
	result, err := c.call("Authenticate", map[string]interface{}{
		"API":      1,
		"Password": c.Password,
	})
	if err != nil {
		return err
	}

	var auth struct {
		Token string `json:"Token"`
	}
	if err := json.Unmarshal(result, &auth); err != nil {
		return err
	}

	c.Token = auth.Token
	return nil
}

func (c *I2PControlClient) Echo(value interface{}) (interface{}, error) {
	result, err := c.call("Echo", map[string]interface{}{
		"Token": c.Token,
		"Echo":  value,
	})
	if err != nil {
		return nil, err
	}

	var echo struct {
		Echo interface{} `json:"Echo"`
	}
	if err := json.Unmarshal(result, &echo); err != nil {
		return nil, err
	}

	return echo.Echo, nil
}

func main() {
	client := &I2PControlClient{
		URL:      "http://localhost:7650/jsonrpc",
		Password: "my-password",
	}

	if err := client.Authenticate(); err != nil {
		panic(err)
	}

	echo, err := client.Echo("test")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Echo: %v\n", echo)
}
```

### Monitoring and Metrics

#### Continuous Monitoring Script

```bash
#!/bin/bash
# monitor-router.sh - Continuous router monitoring

API_URL="http://localhost:7650/jsonrpc"
PASSWORD="your-password"
INTERVAL=30  # seconds

# Authenticate
TOKEN=$(curl -s -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"Authenticate\",\"params\":{\"API\":1,\"Password\":\"$PASSWORD\"}}" \
  | jq -r '.result.Token')

echo "Monitoring started (interval: ${INTERVAL}s)"
echo "Press Ctrl+C to stop"
echo ""

while true; do
  TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
  
  # Get router info
  INFO=$(curl -s -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d "{
      \"jsonrpc\": \"2.0\",
      \"id\": 2,
      \"method\": \"RouterInfo\",
      \"params\": {
        \"Token\": \"$TOKEN\",
        \"i2p.router.uptime\": null,
        \"i2p.router.net.tunnels.participating\": null,
        \"i2p.router.netdb.knownpeers\": null
      }
    }")
  
  UPTIME=$(echo "$INFO" | jq -r '.result["i2p.router.uptime"]')
  TUNNELS=$(echo "$INFO" | jq -r '.result["i2p.router.net.tunnels.participating"]')
  PEERS=$(echo "$INFO" | jq -r '.result["i2p.router.netdb.knownpeers"]')
  
  # Get bandwidth
  BW=$(curl -s -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d "{
      \"jsonrpc\": \"2.0\",
      \"id\": 3,
      \"method\": \"GetRate\",
      \"params\": {
        \"Token\": \"$TOKEN\",
        \"i2p.router.net.bw.inbound.15s\": null,
        \"i2p.router.net.bw.outbound.15s\": null
      }
    }")
  
  BW_IN=$(echo "$BW" | jq -r '.result["i2p.router.net.bw.inbound.15s"]')
  BW_OUT=$(echo "$BW" | jq -r '.result["i2p.router.net.bw.outbound.15s"]')
  
  printf "%s | Uptime: %dms | Tunnels: %d | Peers: %d | BW In: %.2f KB/s | BW Out: %.2f KB/s\n" \
    "$TIMESTAMP" "$UPTIME" "$TUNNELS" "$PEERS" \
    "$(echo "$BW_IN / 1024" | bc -l)" \
    "$(echo "$BW_OUT / 1024" | bc -l)"
  
  sleep "$INTERVAL"
done
```

### Integration with Monitoring Tools

#### Prometheus Exporter (Example)

```python
#!/usr/bin/env python3
# i2pcontrol-exporter.py - Prometheus metrics exporter

from prometheus_client import start_http_server, Gauge
import requests
import time
import sys

class I2PControlExporter:
    def __init__(self, i2pcontrol_url, password, listen_port=9200):
        self.url = i2pcontrol_url
        self.password = password
        self.token = None
        self.request_id = 0
        
        # Define metrics
        self.uptime = Gauge('i2p_router_uptime_ms', 'Router uptime in milliseconds')
        self.tunnels = Gauge('i2p_router_tunnels_participating', 'Participating tunnels')
        self.known_peers = Gauge('i2p_router_known_peers', 'Known peers in NetDB')
        self.bw_in = Gauge('i2p_router_bandwidth_inbound_bps', 'Inbound bandwidth (bytes/sec)')
        self.bw_out = Gauge('i2p_router_bandwidth_outbound_bps', 'Outbound bandwidth (bytes/sec)')
        
        # Start HTTP server for Prometheus scraping
        start_http_server(listen_port)
        print(f"Prometheus exporter listening on port {listen_port}")
    
    def authenticate(self):
        # ... (same as previous Python example)
        pass
    
    def collect_metrics(self):
        try:
            # Authenticate if needed
            if not self.token:
                self.authenticate()
            
            # Collect router info
            # ... (same RPC calls as previous example)
            
            # Update Prometheus metrics
            self.uptime.set(uptime)
            self.tunnels.set(tunnels)
            self.known_peers.set(peers)
            self.bw_in.set(bw_in)
            self.bw_out.set(bw_out)
            
        except Exception as e:
            print(f"Error collecting metrics: {e}")
            self.token = None  # Re-authenticate next time
    
    def run(self, interval=30):
        while True:
            self.collect_metrics()
            time.sleep(interval)

if __name__ == '__main__':
    exporter = I2PControlExporter(
        'http://localhost:7650/jsonrpc',
        'your-password'
    )
    exporter.run()
```

Run exporter:

```bash
python3 i2pcontrol-exporter.py
```

Add to Prometheus config:

```yaml
scrape_configs:
  - job_name: 'i2p'
    static_configs:
      - targets: ['localhost:9200']
```

---

## References

- [I2PControl Specification](https://geti2p.net/spec/i2pcontrol)
- [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification)
- [go-i2p GitHub Repository](https://github.com/go-i2p/go-i2p)
- [Package Documentation](../lib/i2pcontrol/README.md)

## Support

For issues or questions:

1. Check this guide's [Troubleshooting](#troubleshooting) section
2. Review package [README](../lib/i2pcontrol/README.md)
3. Check router logs for errors
4. Open an issue on GitHub

## License

This documentation is part of go-i2p and follows the same license terms.
