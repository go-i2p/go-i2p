package bootstrap

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/netdb/reseed"
	"github.com/go-i2p/logger"
)

// FileBootstrap implements the Bootstrap interface using a local zip or su3 file
type FileBootstrap struct {
	// Path to the local reseed file (zip or su3)
	filePath string
}

// NewFileBootstrap creates a new file bootstrap with the provided file path
func NewFileBootstrap(filePath string) *FileBootstrap {
	log.WithField("file_path", filePath).Info("Initializing file bootstrap")
	return &FileBootstrap{
		filePath: filePath,
	}
}

// GetPeers implements the Bootstrap interface by reading RouterInfos from a local file
func (fb *FileBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"file_path":       fb.filePath,
		"requested_peers": n,
	}).Info("Starting file bootstrap from local reseed file")

	// Check if context is already canceled
	if ctx.Err() != nil {
		log.WithError(ctx.Err()).Warn("File bootstrap canceled by context before starting")
		return nil, fmt.Errorf("file bootstrap canceled: %w", ctx.Err())
	}

	// Validate file exists
	if err := fb.validateFile(); err != nil {
		return nil, err
	}

	// Process file based on type, passing limit to avoid loading excessive RouterInfos into memory
	routerInfos, err := fb.processReseedFile(ctx, n)
	if err != nil {
		return nil, err
	}

	if len(routerInfos) == 0 {
		return nil, fmt.Errorf("no RouterInfos found in reseed file")
	}

	log.WithField("count", len(routerInfos)).Info("Successfully loaded RouterInfos from file")

	// Note: routerInfos already limited by processReseedFile, no need to call limitRouterInfos
	return routerInfos, nil
}

// processReseedFile determines file type and extracts RouterInfos accordingly.
// The limit parameter controls how many RouterInfos are parsed to minimize memory usage.
func (fb *FileBootstrap) processReseedFile(ctx context.Context, limit int) ([]router_info.RouterInfo, error) {
	ext := strings.ToLower(filepath.Ext(fb.filePath))
	log.WithField("extension", ext).Debug("Detected file extension")

	var routerInfos []router_info.RouterInfo
	var err error

	switch ext {
	case ".su3":
		routerInfos, err = fb.processSU3File(ctx, limit)
	case ".zip":
		routerInfos, err = fb.processZipFile(ctx, limit)
	default:
		return nil, fmt.Errorf("unsupported file type: %s (expected .su3 or .zip)", ext)
	}

	if err != nil {
		log.WithError(err).Error("Failed to process reseed file")
		return nil, err
	}

	return routerInfos, nil
}

// limitRouterInfos returns up to n RouterInfos from the provided slice.
// If n <= 0, returns all RouterInfos.
func limitRouterInfos(routerInfos []router_info.RouterInfo, n int) []router_info.RouterInfo {
	if n > 0 && len(routerInfos) > n {
		log.WithFields(logger.Fields{
			"total":     len(routerInfos),
			"requested": n,
			"returning": n,
		}).Debug("Limiting returned peers to requested count")
		return routerInfos[:n]
	}
	return routerInfos
}

// validateFile checks if the file exists and is readable
func (fb *FileBootstrap) validateFile() error {
	log.WithField("file_path", fb.filePath).Debug("Validating reseed file")

	info, err := os.Stat(fb.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.WithField("file_path", fb.filePath).Error("Reseed file does not exist")
			return fmt.Errorf("reseed file does not exist: %s", fb.filePath)
		}
		log.WithError(err).WithField("file_path", fb.filePath).Error("Failed to stat reseed file")
		return fmt.Errorf("failed to access reseed file: %w", err)
	}

	if info.IsDir() {
		log.WithField("file_path", fb.filePath).Error("Reseed path is a directory, not a file")
		return fmt.Errorf("reseed path is a directory: %s", fb.filePath)
	}

	log.WithFields(logger.Fields{
		"file_path":  fb.filePath,
		"size_bytes": info.Size(),
	}).Debug("Reseed file validated successfully")

	return nil
}

// processSU3File reads and processes an SU3 reseed file with a limit on parsed RouterInfos.
// The limit parameter controls memory usage by stopping parse early when enough RouterInfos are obtained.
func (fb *FileBootstrap) processSU3File(ctx context.Context, limit int) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"file_path": fb.filePath,
		"limit":     limit,
	}).Info("Processing SU3 reseed file")

	// Check context before processing
	if ctx.Err() != nil {
		return nil, fmt.Errorf("file bootstrap canceled: %w", ctx.Err())
	}

	// Use the reseed package to process the SU3 file with limit
	reseeder := reseed.NewReseed()
	routerInfos, err := reseeder.ProcessLocalSU3FileWithLimit(fb.filePath, limit)
	if err != nil {
		log.WithError(err).WithField("file_path", fb.filePath).Error("Failed to process SU3 file")
		return nil, fmt.Errorf("failed to process SU3 file: %w", err)
	}

	log.WithFields(logger.Fields{
		"file_path": fb.filePath,
		"count":     len(routerInfos),
	}).Info("Successfully processed SU3 file")

	return routerInfos, nil
}

// processZipFile reads and processes a zip reseed file with a limit on parsed RouterInfos.
// The limit parameter controls memory usage by stopping parse early when enough RouterInfos are obtained.
func (fb *FileBootstrap) processZipFile(ctx context.Context, limit int) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"file_path": fb.filePath,
		"limit":     limit,
	}).Info("Processing zip reseed file")

	// Check context before processing
	if ctx.Err() != nil {
		return nil, fmt.Errorf("file bootstrap canceled: %w", ctx.Err())
	}

	// Use the reseed package to process the zip file with limit
	reseeder := reseed.NewReseed()
	routerInfos, err := reseeder.ProcessLocalZipFileWithLimit(fb.filePath, limit)
	if err != nil {
		log.WithError(err).WithField("file_path", fb.filePath).Error("Failed to process zip file")
		return nil, fmt.Errorf("failed to process zip file: %w", err)
	}

	log.WithFields(logger.Fields{
		"file_path": fb.filePath,
		"count":     len(routerInfos),
	}).Info("Successfully processed zip file")

	return routerInfos, nil
}
