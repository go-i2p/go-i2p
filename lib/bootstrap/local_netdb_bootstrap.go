package bootstrap

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/samber/oops"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2np"
)

// LocalNetDBBootstrap implements the Bootstrap interface by reading RouterInfos
// from a local netDb directory (Java I2P or i2pd compatible)
type LocalNetDBBootstrap struct {
	// Paths to search for existing netDb directories
	searchPaths []string
}

// NewLocalNetDBBootstrap creates a new local netDb bootstrap with default search paths
func NewLocalNetDBBootstrap(cfg *config.BootstrapConfig) *LocalNetDBBootstrap {
	searchPaths := getDefaultNetDBSearchPaths()

	// Add user-configured paths if available
	if cfg != nil && len(cfg.LocalNetDBPaths) > 0 {
		searchPaths = append(cfg.LocalNetDBPaths, searchPaths...)
	}

	return &LocalNetDBBootstrap{
		searchPaths: searchPaths,
	}
}

// NewLocalNetDBBootstrapWithPaths creates a new local netDb bootstrap with custom paths
func NewLocalNetDBBootstrapWithPaths(paths []string) *LocalNetDBBootstrap {
	return &LocalNetDBBootstrap{
		searchPaths: paths,
	}
}

// GetPeers implements the Bootstrap interface by reading RouterInfos from local netDb
func (lb *LocalNetDBBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	// Find all available netDb directories and aggregate peers across them so
	// mixed Java I2P + i2pd installs contribute to the bootstrap set.
	netDBPaths, err := lb.findNetDBDirectories()
	if err != nil {
		return nil, oops.Wrapf(err, "no local netDb found")
	}

	routerInfos, err := lb.readRouterInfosFromDirectories(ctx, netDBPaths, n)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to read RouterInfos from local netDb")
	}

	return routerInfos, nil
}

// findNetDBDirectories searches for existing netDb directories.
func (lb *LocalNetDBBootstrap) findNetDBDirectories() ([]string, error) {
	var paths []string

	for _, path := range lb.searchPaths {
		expanded := expandPath(path)

		// Check if this is a valid netDb directory
		if lb.isValidNetDBDirectory(expanded) {
			paths = append(paths, expanded)
		}
	}

	if len(paths) > 0 {
		sort.Strings(paths)
		return paths, nil
	}

	log.WithField("searched", len(lb.searchPaths)).Warn("no valid netdb directory found in search paths")
	return nil, oops.Errorf("no valid netDb directory found in search paths: %v", lb.searchPaths)
}

// isValidNetDBDirectory checks if a path contains a valid netDb structure
func (lb *LocalNetDBBootstrap) isValidNetDBDirectory(path string) bool {
	// Check if directory exists
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}

	// Check for netDb subdirectories or routerInfo files
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}

	return lb.hasValidNetDBStructure(entries)
}

// hasValidNetDBStructure checks if entries contain valid netDb structure.
func (lb *LocalNetDBBootstrap) hasValidNetDBStructure(entries []os.DirEntry) bool {
	// Look for netDb subdirectories or routerInfo files
	for _, entry := range entries {
		name := entry.Name()

		// Java I2P style: directories like r0, r1, ra, rb, etc.
		if lb.isJavaI2PSubdirectory(entry, name) {
			return true
		}

		// i2pd or direct style: routerInfo-*.dat files
		if lb.isRouterInfoFile(entry, name) {
			return true
		}
	}

	return false
}

// isJavaI2PSubdirectory checks if an entry is a Java I2P style subdirectory.
func (lb *LocalNetDBBootstrap) isJavaI2PSubdirectory(entry os.DirEntry, name string) bool {
	return entry.IsDir() && len(name) == 2 && name[0] == 'r'
}

// isRouterInfoFile checks if an entry is a routerInfo file.
func (lb *LocalNetDBBootstrap) isRouterInfoFile(entry os.DirEntry, name string) bool {
	return !entry.IsDir() && strings.HasPrefix(name, "routerInfo-") && strings.HasSuffix(name, ".dat")
}

// readRouterInfosFromDirectory reads RouterInfo files from a netDb directory
func (lb *LocalNetDBBootstrap) readRouterInfosFromDirectory(ctx context.Context, path string, maxCount int) ([]router_info.RouterInfo, error) {
	routerInfos := make([]router_info.RouterInfo, 0)
	count := 0

	err := filepath.Walk(path, lb.createWalkFunction(ctx, &routerInfos, &count, maxCount))

	if err != nil && err != filepath.SkipAll {
		return nil, err
	}

	if len(routerInfos) == 0 {
		return nil, oops.Errorf("no valid RouterInfo files found in %s", path)
	}

	return routerInfos, nil
}

// readRouterInfosFromDirectories aggregates RouterInfos across multiple valid
// local netDb directories while de-duplicating by router hash.
func (lb *LocalNetDBBootstrap) readRouterInfosFromDirectories(ctx context.Context, paths []string, maxCount int) ([]router_info.RouterInfo, error) {
	seen := make(map[string]struct{})
	aggregated := make([]router_info.RouterInfo, 0)
	var lastErr error

	for _, path := range paths {
		remaining := maxCount
		if maxCount > 0 {
			remaining = maxCount - len(aggregated)
			if remaining <= 0 {
				break
			}
		}

		routerInfos, err := lb.readRouterInfosFromDirectory(ctx, path, remaining)
		if err != nil {
			lastErr = err
			continue
		}

		for _, ri := range routerInfos {
			hash, err := ri.IdentHash()
			if err != nil {
				continue
			}
			key := hash.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			aggregated = append(aggregated, ri)
			if maxCount > 0 && len(aggregated) >= maxCount {
				return aggregated, nil
			}
		}
	}

	if len(aggregated) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, oops.Errorf("no valid RouterInfo files found in %v", paths)
	}

	return aggregated, nil
}

// createWalkFunction creates a filepath.WalkFunc that processes RouterInfo files
func (lb *LocalNetDBBootstrap) createWalkFunction(ctx context.Context, routerInfos *[]router_info.RouterInfo, count *int, maxCount int) filepath.WalkFunc {
	return func(filePath string, info os.FileInfo, err error) error {
		if shouldStopWalk(ctx, *count, maxCount) {
			return filepath.SkipAll
		}

		if !shouldProcessFile(filePath, info, err) {
			return nil
		}

		ri, err := lb.readRouterInfoFromFile(filePath)
		if err != nil {
			lb.logReadFailure(filePath, err)
			return nil
		}

		if err := validateRouterInfoForBootstrap(ri, filePath); err != nil {
			return nil
		}

		*routerInfos = append(*routerInfos, ri)
		*count++

		return nil
	}
}

// logReadFailure logs a failed RouterInfo file read during bootstrap walking.
func (lb *LocalNetDBBootstrap) logReadFailure(filePath string, err error) {
	log.WithError(err).Debug("failed to read RouterInfo file, skipping")
}

// validateRouterInfoForBootstrap checks connectivity, structural integrity, and
// cryptographic signature of a RouterInfo before it is added to the bootstrap set.
// Returns nil on success or an error describing the first failed check.
func validateRouterInfoForBootstrap(ri router_info.RouterInfo, filePath string) error {
	if !HasDirectConnectivity(ri) {
		return oops.Errorf("no direct connectivity")
	}

	if err := ValidateRouterInfo(ri); err != nil {
		return err
	}

	if err := VerifyRouterInfoSignature(ri); err != nil {
		log.WithError(err).Warn("rejecting RouterInfo with invalid signature from local netDb")
		return err
	}

	return nil
}

// shouldStopWalk determines if the walk should be terminated based on context or count
func shouldStopWalk(ctx context.Context, count, maxCount int) bool {
	select {
	case <-ctx.Done():
		return true
	default:
	}

	return maxCount > 0 && count >= maxCount
}

// shouldProcessFile determines if a file should be processed as a RouterInfo file
func shouldProcessFile(filePath string, info os.FileInfo, err error) bool {
	if err != nil {
		return false
	}

	if info.IsDir() {
		return false
	}

	if !strings.HasSuffix(filePath, ".dat") {
		return false
	}

	return strings.Contains(filePath, "routerInfo-")
}

// readRouterInfoFromFile reads and parses a single RouterInfo file
func (lb *LocalNetDBBootstrap) readRouterInfoFromFile(filePath string) (router_info.RouterInfo, error) {
	data, err := readRouterInfoBytes(filePath)
	if err != nil {
		return router_info.RouterInfo{}, err
	}

	ri, _, err := router_info.ReadRouterInfo(data)
	if err != nil {
		return router_info.RouterInfo{}, oops.Wrapf(err, "failed to parse RouterInfo")
	}

	if err := validateRouterInfoFreshness(ri); err != nil {
		return router_info.RouterInfo{}, err
	}

	return ri, nil
}

// readRouterInfoBytes opens and reads a RouterInfo file, limiting the read size
// to 64 KB to prevent OOM from maliciously large files.
// Uses the centralized MaxRouterInfoSize limit from lib/i2np.
func readRouterInfoBytes(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to open file")
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, i2np.MaxRouterInfoSize))
	if err != nil {
		return nil, oops.Wrapf(err, "failed to read file")
	}
	if len(data) == 0 {
		return nil, oops.Errorf("router info file is empty")
	}
	return data, nil
}

// validateRouterInfoFreshness checks that a RouterInfo's published date is within
// the acceptable age range (not expired, not future-dated beyond clock skew tolerance).
func validateRouterInfoFreshness(ri router_info.RouterInfo) error {
	const routerInfoMaxAge = 48 * time.Hour
	const maxClockSkew = 10 * time.Minute

	publishedDate := ri.Published()
	if publishedDate == nil {
		return nil
	}

	publishedTime := publishedDate.Time()
	age := time.Since(publishedTime)
	if age < -maxClockSkew {
		return oops.Errorf("RouterInfo has future timestamp (published %v in the future, max clock skew %v)", -age.Round(time.Second), maxClockSkew)
	}
	if age > routerInfoMaxAge {
		return oops.Errorf("RouterInfo expired (published %v ago, max age %v)", age.Round(time.Minute), routerInfoMaxAge)
	}
	return nil
}

// getDefaultNetDBSearchPaths returns default search paths for netDb directories
// based on the operating system. It uses a table-driven approach with path templates.
func getDefaultNetDBSearchPaths() []string {
	homeDir := getHomeDir()

	// Determine path templates for the current OS
	var pathTemplates []string
	switch runtime.GOOS {
	case "linux":
		pathTemplates = []string{
			"~/.i2p/netDb",
			"/var/lib/i2p/i2p-config/netDb",
			"/usr/share/i2p/netDb",
			"~/.i2pd/netDb",
			"/var/lib/i2pd/netDb",
		}
	case "darwin":
		pathTemplates = []string{
			"~/Library/Application Support/i2p/netDb",
			"~/.i2p/netDb",
			"~/Library/Application Support/i2pd/netDb",
			"~/.i2pd/netDb",
		}
	case "windows":
		appData := getWindowsAppData(homeDir)
		return []string{
			filepath.Join(appData, "I2P/netDb"),
			filepath.Join(homeDir, "i2p/netDb"),
			filepath.Join(appData, "i2pd/netDb"),
		}
	case "freebsd", "openbsd", "netbsd":
		pathTemplates = []string{
			"/usr/local/etc/i2p/netDb",
			"/usr/local/etc/i2pd/netDb",
			"/var/db/i2p/netDb",
			"~/.i2p/netDb",
			"~/.i2pd/netDb",
		}
	default:
		pathTemplates = []string{
			"~/.i2p/netDb",
			"~/.i2pd/netDb",
		}
	}

	// Expand path templates for non-Windows OSes
	return expandPathTemplates(pathTemplates, homeDir)
}

// expandPathTemplates expands path templates containing ~ to the actual home directory.
func expandPathTemplates(templates []string, homeDir string) []string {
	paths := make([]string, 0, len(templates))
	for _, template := range templates {
		if strings.HasPrefix(template, "~/") {
			paths = append(paths, filepath.Join(homeDir, template[2:]))
		} else {
			paths = append(paths, template)
		}
	}
	return paths
}

// getHomeDir returns the user's home directory with fallback to "~".
func getHomeDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.WithError(err).Warn("failed to get user home directory")
		return ""
	}
	return homeDir
}

// getWindowsAppData returns the Windows APPDATA directory with fallback.
func getWindowsAppData(homeDir string) string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		log.Warn("APPDATA environment variable not set, using default path")
		return filepath.Join(homeDir, "AppData", "Roaming")
	}
	return appData
}

// expandPath expands environment variables and ~ in paths
func expandPath(path string) string {
	// Expand ~ to home directory
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(homeDir, path[2:])
		}
	}

	// Expand environment variables
	path = os.ExpandEnv(path)

	return path
}
