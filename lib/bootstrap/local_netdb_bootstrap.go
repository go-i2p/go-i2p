package bootstrap

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

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

	log.WithField("search_paths", searchPaths).Info("Initializing local netDb bootstrap")
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
	log.WithField("requested_peers", n).Info("Starting local netDb bootstrap")

	// Find the first available netDb directory
	netDbPath, err := lb.findNetDbDirectory()
	if err != nil {
		return nil, fmt.Errorf("no local netDb found: %w", err)
	}

	log.WithField("path", netDbPath).Info("Found local netDb directory")

	// Read RouterInfos from the directory
	routerInfos, err := lb.readRouterInfosFromDirectory(ctx, netDbPath, n)
	if err != nil {
		return nil, fmt.Errorf("failed to read RouterInfos from local netDb: %w", err)
	}

	log.WithField("count", len(routerInfos)).Info("Successfully loaded RouterInfos from local netDb")
	return routerInfos, nil
}

// findNetDbDirectory searches for an existing netDb directory
func (lb *LocalNetDbBootstrap) findNetDbDirectory() (string, error) {
	for _, path := range lb.searchPaths {
		expanded := expandPath(path)

		// Check if this is a valid netDb directory
		if lb.isValidNetDbDirectory(expanded) {
			log.WithField("path", expanded).Debug("Found valid netDb directory")
			return expanded, nil
		}
	}

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
			log.WithError(err).WithField("file", filePath).Debug("Failed to read RouterInfo file, skipping")
			return nil
		}

		*routerInfos = append(*routerInfos, ri)
		*count++

		return nil
	}
}

// shouldStopWalk determines if the walk should be terminated based on context or count
func shouldStopWalk(ctx context.Context, count int, maxCount int) bool {
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

	return ri, nil
}

// getDefaultNetDbSearchPaths returns default search paths for netDb directories
// based on the operating system
func getDefaultNetDbSearchPaths() []string {
	paths := make([]string, 0)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.WithError(err).Warn("Failed to get user home directory")
		homeDir = "~"
	}

	switch runtime.GOOS {
	case "linux":
		// Java I2P default locations on Linux
		paths = append(paths,
			filepath.Join(homeDir, ".i2p/netDb"),
			"/var/lib/i2p/i2p-config/netDb",
			"/usr/share/i2p/netDb",
		)
		// i2pd default locations on Linux
		paths = append(paths,
			filepath.Join(homeDir, ".i2pd/netDb"),
			"/var/lib/i2pd/netDb",
		)

	case "darwin":
		// Java I2P default locations on macOS
		paths = append(paths,
			filepath.Join(homeDir, "Library/Application Support/i2p/netDb"),
			filepath.Join(homeDir, ".i2p/netDb"),
		)
		// i2pd default locations on macOS
		paths = append(paths,
			filepath.Join(homeDir, "Library/Application Support/i2pd/netDb"),
			filepath.Join(homeDir, ".i2pd/netDb"),
		)

	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(homeDir, "AppData", "Roaming")
		}

		// Java I2P default locations on Windows
		paths = append(paths,
			filepath.Join(appData, "I2P/netDb"),
			filepath.Join(homeDir, "i2p/netDb"),
		)
		// i2pd default locations on Windows
		paths = append(paths,
			filepath.Join(appData, "i2pd/netDb"),
		)

	default:
		// Generic fallback
		paths = append(paths,
			filepath.Join(homeDir, ".i2p/netDb"),
			filepath.Join(homeDir, ".i2pd/netDb"),
		)
	}

	return paths
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
