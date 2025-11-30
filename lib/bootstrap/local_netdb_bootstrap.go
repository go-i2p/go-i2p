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

	// Check for netDb subdirectories (r0-r9, ra-rz for Java I2P style)
	// or routerInfo-* files (for i2pd style)
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}

	// Look for netDb subdirectories or routerInfo files
	hasSubdirs := false
	hasRouterInfoFiles := false

	for _, entry := range entries {
		name := entry.Name()

		// Java I2P style: directories like r0, r1, ra, rb, etc.
		if entry.IsDir() && len(name) == 2 && name[0] == 'r' {
			hasSubdirs = true
			break
		}

		// i2pd or direct style: routerInfo-*.dat files
		if !entry.IsDir() && strings.HasPrefix(name, "routerInfo-") && strings.HasSuffix(name, ".dat") {
			hasRouterInfoFiles = true
			break
		}
	}

	return hasSubdirs || hasRouterInfoFiles
}

// readRouterInfosFromDirectory reads RouterInfo files from a netDb directory
func (lb *LocalNetDbBootstrap) readRouterInfosFromDirectory(ctx context.Context, path string, maxCount int) ([]router_info.RouterInfo, error) {
	routerInfos := make([]router_info.RouterInfo, 0)
	count := 0

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			return nil // Skip files with errors
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process .dat files that look like RouterInfo files
		if !strings.HasSuffix(filePath, ".dat") {
			return nil
		}

		if !strings.Contains(filePath, "routerInfo-") {
			return nil
		}

		// Try to read and parse the RouterInfo
		ri, err := lb.readRouterInfoFromFile(filePath)
		if err != nil {
			// Log but don't fail - some files might be corrupted
			log.WithError(err).WithField("file", filePath).Debug("Failed to read RouterInfo file, skipping")
			return nil
		}

		routerInfos = append(routerInfos, ri)
		count++

		// Stop if we have enough
		if maxCount > 0 && count >= maxCount {
			return filepath.SkipAll
		}

		return nil
	})

	if err != nil && err != filepath.SkipAll {
		return nil, err
	}

	if len(routerInfos) == 0 {
		return nil, fmt.Errorf("no valid RouterInfo files found in %s", path)
	}

	return routerInfos, nil
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
