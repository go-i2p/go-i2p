package naming

import (
	"bufio"
	"embed"
	"fmt"
	"strings"
	"sync"

	"github.com/go-i2p/common/base64"
	"github.com/go-i2p/logger"
)

//go:embed hosts.txt
var defaultHostsFS embed.FS

// HostsTxtResolver resolves .i2p hostnames using an in-memory map
// loaded from a hosts.txt file. The default embedded hosts.txt is
// from the Java I2P router distribution.
type HostsTxtResolver struct {
	mu    sync.RWMutex
	hosts map[string][]byte // hostname -> decoded destination bytes
}

// NewHostsTxtResolver creates a resolver preloaded with the embedded
// default hosts.txt from the Java I2P router.
func NewHostsTxtResolver() (*HostsTxtResolver, error) {
	data, err := defaultHostsFS.ReadFile("hosts.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded hosts.txt: %w", err)
	}
	return newResolverFromData(data)
}

// newResolverFromData parses hosts.txt content and builds a resolver.
func newResolverFromData(data []byte) (*HostsTxtResolver, error) {
	r := &HostsTxtResolver{
		hosts: make(map[string][]byte),
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hostname, destBytes, err := parseHostsLine(line)
		if err != nil {
			log.WithFields(logger.Fields{
				"at":    "naming.newResolverFromData",
				"line":  line[:min(len(line), 40)],
				"error": err.Error(),
			}).Warn("skipping_invalid_hosts_line")
			continue
		}
		r.hosts[hostname] = destBytes
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan hosts.txt: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":    "naming.NewHostsTxtResolver",
		"count": len(r.hosts),
	}).Info("hosts_txt_resolver_initialized")

	return r, nil
}

// parseHostsLine parses a single "hostname=base64destination" line.
func parseHostsLine(line string) (string, []byte, error) {
	idx := strings.IndexByte(line, '=')
	if idx < 1 {
		return "", nil, fmt.Errorf("missing '=' separator")
	}

	hostname := strings.TrimSpace(line[:idx])
	b64dest := strings.TrimSpace(line[idx+1:])

	if hostname == "" {
		return "", nil, fmt.Errorf("empty hostname")
	}
	if b64dest == "" {
		return "", nil, fmt.Errorf("empty destination for %s", hostname)
	}

	destBytes, err := base64.I2PEncoding.DecodeString(b64dest)
	if err != nil {
		return "", nil, fmt.Errorf("invalid base64 destination for %s: %w", hostname, err)
	}

	return hostname, destBytes, nil
}

// ResolveHostname resolves an I2P hostname to its raw Destination bytes.
// Returns the destination bytes and nil on success, or nil and an error
// if the hostname is not found.
func (r *HostsTxtResolver) ResolveHostname(hostname string) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	dest, ok := r.hosts[hostname]
	if !ok {
		return nil, fmt.Errorf("hostname not found: %s", hostname)
	}

	// Return a copy to prevent callers from mutating the internal map
	result := make([]byte, len(dest))
	copy(result, dest)
	return result, nil
}

// Size returns the number of hostnames loaded in the resolver.
func (r *HostsTxtResolver) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.hosts)
}
