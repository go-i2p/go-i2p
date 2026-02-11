package bootstrap

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/go-i2p/logger"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
)

// LocalNetDbBootstrap implements the Bootstrap interface by reading RouterInfos
// from a local netDb directory (Java I2P or i2pd compatible)
type LocalNetDbBootstrap struct {
	// Paths to search for existing netDb directories
	searchPaths []string
}

// NewLocalNetDbBootstrap creates a new local netDb bootstrap with default search paths
func NewLocalNetDbBootstrap(cfg *config.BootstrapConfig) *LocalNetDbBootstrap {
	searchPaths := getDefaultNetDbSearchPaths()

	// Add user-configured paths if available
	if cfg != nil && len(cfg.LocalNetDbPaths) > 0 {
		searchPaths = append(cfg.LocalNetDbPaths, searchPaths...)
	}

	log.WithFields(logger.Fields{
		"at":                "(LocalNetDbBootstrap) NewLocalNetDbBootstrap",
		"phase":             "bootstrap",
		"step":              1,
		"reason":            "initializing local netdb bootstrap",
		"search_path_count": len(searchPaths),
		"search_paths":      searchPaths,
	}).Info("initializing local netDb bootstrap")
	return &LocalNetDbBootstrap{
		searchPaths: searchPaths,
	}
}

// NewLocalNetDbBootstrapWithPaths creates a new local netDb bootstrap with custom paths
func NewLocalNetDbBootstrapWithPaths(paths []string) *LocalNetDbBootstrap {
	log.WithField("custom_paths", paths).Info("Initializing local netDb bootstrap with custom paths")
	return &LocalNetDbBootstrap{
		searchPaths: paths,
	}
}

// GetPeers implements the Bootstrap interface by reading RouterInfos from local netDb
func (lb *LocalNetDbBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"at":              "(LocalNetDbBootstrap) GetPeers",
		"phase":           "bootstrap",
		"step":            "start",
		"reason":          "searching for existing I2P netdb directories",
		"requested_peers": n,
		"search_paths":    len(lb.searchPaths),
	}).Info("starting local netDb bootstrap")

	// Find the first available netDb directory
	netDbPath, err := lb.findNetDbDirectory()
	if err != nil {
		return nil, fmt.Errorf("no local netDb found: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":       "(LocalNetDbBootstrap) GetPeers",
		"phase":    "bootstrap",
		"step":     "directory_found",
		"reason":   "found valid netdb directory",
		"path":     netDbPath,
		"searched": len(lb.searchPaths),
	}).Info("found local netDb directory")

	// Read RouterInfos from the directory
	routerInfos, err := lb.readRouterInfosFromDirectory(ctx, netDbPath, n)
	if err != nil {
		return nil, fmt.Errorf("failed to read RouterInfos from local netDb: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":           "(LocalNetDbBootstrap) GetPeers",
		"phase":        "bootstrap",
		"step":         "complete",
		"reason":       "successfully loaded routers from local netdb",
		"router_count": len(routerInfos),
		"requested":    n,
		"netdb_path":   netDbPath,
	}).Info("successfully loaded RouterInfos from local netDb")
	return routerInfos, nil
}

// findNetDbDirectory searches for an existing netDb directory
func (lb *LocalNetDbBootstrap) findNetDbDirectory() (string, error) {
	log.WithFields(logger.Fields{
		"at":         "(LocalNetDbBootstrap) findNetDbDirectory",
		"phase":      "bootstrap",
		"reason":     "searching for existing netdb directory",
		"path_count": len(lb.searchPaths),
	}).Debug("searching for netdb directory")

	for i, path := range lb.searchPaths {
		expanded := expandPath(path)

		log.WithFields(logger.Fields{
			"at":     "(LocalNetDbBootstrap) findNetDbDirectory",
			"phase":  "bootstrap",
			"reason": "checking search path",
			"index":  i + 1,
			"total":  len(lb.searchPaths),
			"path":   expanded,
		}).Debug("checking netdb search path")

		// Check if this is a valid netDb directory
		if lb.isValidNetDbDirectory(expanded) {
			log.WithFields(logger.Fields{
				"at":      "(LocalNetDbBootstrap) findNetDbDirectory",
				"phase":   "bootstrap",
				"reason":  "found valid netdb directory",
				"path":    expanded,
				"checked": i + 1,
			}).Debug("found valid netDb directory")
			return expanded, nil
		}
	}

	log.WithFields(logger.Fields{
		"at":         "(LocalNetDbBootstrap) findNetDbDirectory",
		"phase":      "bootstrap",
		"reason":     "no valid netdb directory found",
		"searched":   len(lb.searchPaths),
		"paths":      lb.searchPaths,
		"os":         runtime.GOOS,
		"impact":     "local netDb bootstrap will fail",
		"suggestion": "install Java I2P or i2pd to populate local netDb",
	}).Warn("no valid netdb directory found in search paths")
	return "", fmt.Errorf("no valid netDb directory found in search paths: %v", lb.searchPaths)
}

// isValidNetDbDirectory checks if a path contains a valid netDb structure
func (lb *LocalNetDbBootstrap) isValidNetDbDirectory(path string) bool {
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

	return lb.hasValidNetDbStructure(entries)
}

// hasValidNetDbStructure checks if entries contain valid netDb structure.
func (lb *LocalNetDbBootstrap) hasValidNetDbStructure(entries []os.DirEntry) bool {
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
func (lb *LocalNetDbBootstrap) isJavaI2PSubdirectory(entry os.DirEntry, name string) bool {
	return entry.IsDir() && len(name) == 2 && name[0] == 'r'
}

// isRouterInfoFile checks if an entry is a routerInfo file.
func (lb *LocalNetDbBootstrap) isRouterInfoFile(entry os.DirEntry, name string) bool {
	return !entry.IsDir() && strings.HasPrefix(name, "routerInfo-") && strings.HasSuffix(name, ".dat")
}

// readRouterInfosFromDirectory reads RouterInfo files from a netDb directory
func (lb *LocalNetDbBootstrap) readRouterInfosFromDirectory(ctx context.Context, path string, maxCount int) ([]router_info.RouterInfo, error) {
	routerInfos := make([]router_info.RouterInfo, 0)
	count := 0

	err := filepath.Walk(path, lb.createWalkFunction(ctx, &routerInfos, &count, maxCount))

	if err != nil && err != filepath.SkipAll {
		return nil, err
	}

	if len(routerInfos) == 0 {
		return nil, fmt.Errorf("no valid RouterInfo files found in %s", path)
	}

	return routerInfos, nil
}

// createWalkFunction creates a filepath.WalkFunc that processes RouterInfo files
func (lb *LocalNetDbBootstrap) createWalkFunction(ctx context.Context, routerInfos *[]router_info.RouterInfo, count *int, maxCount int) filepath.WalkFunc {
	return func(filePath string, info os.FileInfo, err error) error {
		if shouldStopWalk(ctx, *count, maxCount) {
			return filepath.SkipAll
		}

		if !shouldProcessFile(filePath, info, err) {
			return nil
		}

		ri, err := lb.readRouterInfoFromFile(filePath)
		if err != nil {
			log.WithError(err).WithFields(logger.Fields{
				"at":         "(LocalNetDbBootstrap) createWalkFunction",
				"phase":      "bootstrap",
				"reason":     "failed to read RouterInfo file",
				"file":       filePath,
				"error_type": fmt.Sprintf("%T", err),
				"action":     "skipping",
			}).Debug("failed to read RouterInfo file, skipping")
			return nil
		}

		// CRITICAL FIX #1: Pre-filter for direct NTCP2 connectivity BEFORE adding to bootstrap peers
		// This prevents ERROR logs from common package when checking introducer-only addresses
		if !HasDirectConnectivity(ri) {
			log.WithFields(logger.Fields{
				"at":     "(LocalNetDbBootstrap) createWalkFunction",
				"phase":  "pre-filter",
				"reason": "no direct NTCP2 connectivity",
				"file":   filePath,
			}).Debug("skipping RouterInfo without direct NTCP2 connectivity")
			return nil
		}

		// Validate structural integrity
		if err := ValidateRouterInfo(ri); err != nil {
			log.WithFields(logger.Fields{
				"at":     "(LocalNetDbBootstrap) createWalkFunction",
				"phase":  "validation",
				"reason": "invalid RouterInfo",
				"file":   filePath,
				"error":  err.Error(),
			}).Debug("skipping invalid RouterInfo from local netDb")
			return nil
		}

		// Verify cryptographic signature
		if err := VerifyRouterInfoSignature(ri); err != nil {
			log.WithFields(logger.Fields{
				"at":     "(LocalNetDbBootstrap) createWalkFunction",
				"phase":  "validation",
				"reason": "signature verification failed",
				"file":   filePath,
				"error":  err.Error(),
			}).Warn("rejecting RouterInfo with invalid signature from local netDb")
			return nil
		}

		*routerInfos = append(*routerInfos, ri)
		*count++

		return nil
	}
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
func (lb *LocalNetDbBootstrap) readRouterInfoFromFile(filePath string) (router_info.RouterInfo, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return router_info.RouterInfo{}, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return router_info.RouterInfo{}, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse RouterInfo
	ri, _, err := router_info.ReadRouterInfo(data)
	if err != nil {
		return router_info.RouterInfo{}, fmt.Errorf("failed to parse RouterInfo: %w", err)
	}

	// Validate expiration: RouterInfos are valid for 24 hours per I2P specification
	const routerInfoMaxAge = 24 * time.Hour
	// Allow a small clock skew tolerance for future-dated RouterInfos
	const maxClockSkew = 10 * time.Minute
	publishedDate := ri.Published()
	if publishedDate != nil {
		publishedTime := publishedDate.Time()
		age := time.Since(publishedTime)
		if age < -maxClockSkew {
			// RouterInfo is dated in the future beyond clock skew tolerance.
			// This may indicate a forged timestamp to bypass expiration checks.
			return router_info.RouterInfo{}, fmt.Errorf("RouterInfo has future timestamp (published %v in the future, max clock skew %v)", -age.Round(time.Second), maxClockSkew)
		}
		if age > routerInfoMaxAge {
			return router_info.RouterInfo{}, fmt.Errorf("RouterInfo expired (published %v ago, max age %v)", age.Round(time.Minute), routerInfoMaxAge)
		}
	}

	return ri, nil
}

// getDefaultNetDbSearchPaths returns default search paths for netDb directories
// based on the operating system. It delegates to OS-specific helper functions.
func getDefaultNetDbSearchPaths() []string {
	homeDir := getHomeDir()

	switch runtime.GOOS {
	case "linux":
		return getLinuxNetDbPaths(homeDir)
	case "darwin":
		return getDarwinNetDbPaths(homeDir)
	case "windows":
		return getWindowsNetDbPaths(homeDir)
	default:
		return getGenericNetDbPaths(homeDir)
	}
}

// getHomeDir returns the user's home directory with fallback to "~".
func getHomeDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "getHomeDir",
			"phase":  "bootstrap",
			"reason": "failed to determine user home directory",
		}).Warn("failed to get user home directory")
		return "~"
	}
	return homeDir
}

// getLinuxNetDbPaths returns netDb search paths for Linux systems.
func getLinuxNetDbPaths(homeDir string) []string {
	return []string{
		// Java I2P default locations on Linux
		filepath.Join(homeDir, ".i2p/netDb"),
		"/var/lib/i2p/i2p-config/netDb",
		"/usr/share/i2p/netDb",
		// i2pd default locations on Linux
		filepath.Join(homeDir, ".i2pd/netDb"),
		"/var/lib/i2pd/netDb",
	}
}

// getDarwinNetDbPaths returns netDb search paths for macOS systems.
func getDarwinNetDbPaths(homeDir string) []string {
	return []string{
		// Java I2P default locations on macOS
		filepath.Join(homeDir, "Library/Application Support/i2p/netDb"),
		filepath.Join(homeDir, ".i2p/netDb"),
		// i2pd default locations on macOS
		filepath.Join(homeDir, "Library/Application Support/i2pd/netDb"),
		filepath.Join(homeDir, ".i2pd/netDb"),
	}
}

// getWindowsNetDbPaths returns netDb search paths for Windows systems.
func getWindowsNetDbPaths(homeDir string) []string {
	appData := getWindowsAppData(homeDir)
	return []string{
		// Java I2P default locations on Windows
		filepath.Join(appData, "I2P/netDb"),
		filepath.Join(homeDir, "i2p/netDb"),
		// i2pd default locations on Windows
		filepath.Join(appData, "i2pd/netDb"),
	}
}

// getWindowsAppData returns the Windows APPDATA directory with fallback.
func getWindowsAppData(homeDir string) string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		log.WithFields(logger.Fields{
			"at":            "getWindowsAppData",
			"phase":         "bootstrap",
			"reason":        "appdata_env_missing",
			"os":            "windows",
			"fallback_path": filepath.Join(homeDir, "AppData", "Roaming"),
			"impact":        "using default Windows AppData location",
		}).Warn("APPDATA environment variable not set, using default path")
		return filepath.Join(homeDir, "AppData", "Roaming")
	}
	return appData
}

// getGenericNetDbPaths returns generic fallback netDb search paths.
func getGenericNetDbPaths(homeDir string) []string {
	return []string{
		filepath.Join(homeDir, ".i2p/netDb"),
		filepath.Join(homeDir, ".i2pd/netDb"),
	}
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
