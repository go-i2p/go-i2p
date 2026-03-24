package naming

import (
	"bufio"
	"crypto/sha256"
	"embed"
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-i2p/common/base64"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/logger"
)

// LeaseSetLookup is the interface required to look up LeaseSets in the NetDB.
// This is used to resolve .b32.i2p addresses to full destinations.
type LeaseSetLookup interface {
	// GetLeaseSet returns a channel that yields the LeaseSet for the given hash,
	// or a closed channel if not found.
	GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet
}

//go:embed hosts.txt
var defaultHostsFS embed.FS

// HostsTxtResolver resolves .i2p hostnames using an in-memory map
// loaded from a hosts.txt file. The default embedded hosts.txt is
// from the Java I2P router distribution.
//
// For .b32.i2p addresses, if a NetDB is configured, the resolver will
// look up the destination in the NetDB and return the full destination bytes.
type HostsTxtResolver struct {
	mu    sync.RWMutex
	hosts map[string][]byte // hostname -> decoded destination bytes
	netdb LeaseSetLookup    // optional: for resolving .b32.i2p addresses
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

// SetNetDB configures the resolver to use the provided NetDB for .b32.i2p lookups.
// When a NetDB is set, Resolve() will perform LeaseSet lookups for b32 addresses
// to return the full destination bytes instead of just the hash.
func (r *HostsTxtResolver) SetNetDB(netdb LeaseSetLookup) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.netdb = netdb
}

// AddHostsFile loads additional hostname entries from a file on disk.
// This can be called after initialization to add address book subscriptions
// or user-maintained hosts files. Entries from the file override any existing
// entries with the same hostname.
func (r *HostsTxtResolver) AddHostsFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read hosts file %s: %w", path, err)
	}

	return r.addHostsData(data, path)
}

// addHostsData parses hosts.txt content and adds entries to the resolver.
func (r *HostsTxtResolver) addHostsData(data []byte, source string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	added := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hostname, destBytes, err := parseHostsLine(line)
		if err != nil {
			log.WithFields(logger.Fields{
				"at":     "naming.addHostsData",
				"source": source,
				"line":   line[:min(len(line), 40)],
				"error":  err.Error(),
			}).Warn("skipping_invalid_hosts_line")
			continue
		}
		r.hosts[hostname] = destBytes
		added++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to scan hosts data from %s: %w", source, err)
	}

	log.WithFields(logger.Fields{
		"at":     "naming.AddHostsFile",
		"source": source,
		"added":  added,
		"total":  len(r.hosts),
	}).Info("hosts_file_loaded")

	return nil
}

// LoadAddressBooksFromDir loads all hosts.txt files from a directory.
// Files are loaded in alphabetical order, with later files overriding
// earlier entries for the same hostname.
func (r *HostsTxtResolver) LoadAddressBooksFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			log.WithFields(logger.Fields{
				"at":  "naming.LoadAddressBooksFromDir",
				"dir": dir,
			}).Debug("address_book_directory_not_found")
			return nil // Not an error if directory doesn't exist
		}
		return fmt.Errorf("failed to read address book directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if err := r.AddHostsFile(path); err != nil {
			log.WithFields(logger.Fields{
				"at":    "naming.LoadAddressBooksFromDir",
				"path":  path,
				"error": err.Error(),
			}).Warn("failed_to_load_address_book_file")
			// Continue loading other files
		}
	}

	return nil
}

// b32Encoding is the base32 encoding used for .b32.i2p addresses.
// I2P uses lowercase base32 without padding.
var b32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ResolveB32Address is a package-level convenience function to decode a .b32.i2p address.
// It returns the 32-byte hash, not the full destination.
// For full destination resolution with NetDB lookup, use HostsTxtResolver.Resolve().
func ResolveB32Address(address string) ([]byte, error) {
	return decodeB32Address(address)
}

// DestinationToB32 is a package-level convenience function to convert destination bytes
// to a .b32.i2p address string.
func DestinationToB32(destBytes []byte) string {
	hash := sha256.Sum256(destBytes)
	return b32Encoding.EncodeToString(hash[:]) + ".b32.i2p"
}

// decodeB32Address decodes a .b32.i2p address to its raw hash bytes.
func decodeB32Address(address string) ([]byte, error) {
	// Strip .b32.i2p suffix if present
	address = strings.ToLower(address)
	if strings.HasSuffix(address, ".b32.i2p") {
		address = strings.TrimSuffix(address, ".b32.i2p")
	}

	// B32 addresses are 52 characters (256 bits in base32)
	if len(address) != 52 {
		return nil, fmt.Errorf("invalid b32 address length: %d (expected 52)", len(address))
	}

	hashBytes, err := b32Encoding.DecodeString(address)
	if err != nil {
		return nil, fmt.Errorf("invalid b32 encoding: %w", err)
	}

	if len(hashBytes) != 32 {
		return nil, fmt.Errorf("decoded b32 hash is %d bytes (expected 32)", len(hashBytes))
	}

	return hashBytes, nil
}

// ResolveB32Address resolves a .b32.i2p address to its raw hash bytes.
// The input can be either just the 52-character hash or the full address
// including the ".b32.i2p" suffix.
//
// Note: B32 addresses are a hash of the destination, so this function returns
// the hash bytes (32 bytes), not the full destination. To resolve to a full
// destination, use the Resolve method with a NetDB configured.
func (r *HostsTxtResolver) ResolveB32Address(address string) ([]byte, error) {
	return decodeB32Address(address)
}

// DestinationToB32 converts a raw Destination to its .b32.i2p address.
// The destination bytes are SHA-256 hashed and base32-encoded.
func (r *HostsTxtResolver) DestinationToB32(destBytes []byte) string {
	return DestinationToB32(destBytes)
}

// Resolve resolves an I2P address (either a hostname or .b32.i2p address).
// For regular hostnames, returns the full Destination bytes.
// For .b32.i2p addresses:
//   - If a NetDB is configured, performs a LeaseSet lookup and returns the full destination.
//   - If no NetDB is configured, returns the 32-byte hash with isHash=true.
func (r *HostsTxtResolver) Resolve(address string) ([]byte, bool, error) {
	address = strings.ToLower(strings.TrimSpace(address))

	// Handle .b32.i2p addresses
	if strings.HasSuffix(address, ".b32.i2p") {
		hashBytes, err := r.ResolveB32Address(address)
		if err != nil {
			return nil, false, err
		}

		// If we have a NetDB, perform the LeaseSet lookup
		r.mu.RLock()
		netdb := r.netdb
		r.mu.RUnlock()

		if netdb != nil {
			dest, err := r.lookupDestinationFromNetDB(hashBytes, netdb)
			if err != nil {
				return nil, false, err
			}
			return dest, false, nil // Full destination resolved
		}

		// No NetDB configured - return hash and indicate lookup is needed
		return hashBytes, true, nil
	}

	// Handle regular .i2p hostnames
	dest, err := r.ResolveHostname(address)
	if err != nil {
		return nil, false, err
	}
	return dest, false, nil
}

// lookupDestinationFromNetDB performs a LeaseSet lookup and extracts the destination.
func (r *HostsTxtResolver) lookupDestinationFromNetDB(hashBytes []byte, netdb LeaseSetLookup) ([]byte, error) {
	var hash common.Hash
	copy(hash[:], hashBytes)

	lsChan := netdb.GetLeaseSet(hash)
	if lsChan == nil {
		return nil, fmt.Errorf("b32 address %x not found in NetDB", hashBytes[:8])
	}

	ls, ok := <-lsChan
	if !ok {
		return nil, fmt.Errorf("b32 address %x not found in NetDB", hashBytes[:8])
	}

	// Extract the destination from the LeaseSet
	dest := ls.Destination()
	if !dest.IsValid() {
		return nil, fmt.Errorf("LeaseSet for %x has invalid destination", hashBytes[:8])
	}

	destBytes, err := dest.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize destination for %x: %w", hashBytes[:8], err)
	}

	log.WithFields(logger.Fields{
		"at":   "naming.lookupDestinationFromNetDB",
		"hash": fmt.Sprintf("%x...", hashBytes[:8]),
	}).Debug("resolved b32 address from NetDB")

	return destBytes, nil
}
