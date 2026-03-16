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
	log.WithFields(logger.Fields{
		"at":        "(FileBootstrap) NewFileBootstrap",
		"phase":     "bootstrap",
		"step":      1,
		"reason":    "initializing file bootstrap from local reseed file",
		"file_path": filePath,
	}).Info("initializing file bootstrap")
	return &FileBootstrap{
		filePath: filePath,
	}
}

// GetPeers implements the Bootstrap interface by reading RouterInfos from a local file
func (fb *FileBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"at":              "(FileBootstrap) GetPeers",
		"phase":           "bootstrap",
		"step":            "start",
		"reason":          "reading routers from local reseed file",
		"file_path":       fb.filePath,
		"requested_peers": n,
	}).Info("starting file bootstrap from local reseed file")

	// Check if context is already canceled
	if ctx.Err() != nil {
		log.WithError(ctx.Err()).WithFields(logger.Fields{
			"at":     "(FileBootstrap) GetPeers",
			"phase":  "bootstrap",
			"reason": "context canceled before file bootstrap",
		}).Warn("file bootstrap canceled by context before starting")
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

	log.WithFields(logger.Fields{
		"at":           "(FileBootstrap) GetPeers",
		"phase":        "bootstrap",
		"step":         "complete",
		"reason":       "successfully loaded routers from file",
		"router_count": len(routerInfos),
		"requested":    n,
		"file_path":    fb.filePath,
	}).Info("successfully loaded RouterInfos from file")

	// Note: routerInfos already limited by processReseedFile, no need to call limitRouterInfos
	return routerInfos, nil
}

// processReseedFile determines file type and extracts RouterInfos accordingly.
// The limit parameter controls how many RouterInfos are parsed to minimize memory usage.
func (fb *FileBootstrap) processReseedFile(ctx context.Context, limit int) ([]router_info.RouterInfo, error) {
	ext := strings.ToLower(filepath.Ext(fb.filePath))
	log.WithFields(logger.Fields{
		"at":        "(FileBootstrap) processReseedFile",
		"phase":     "bootstrap",
		"reason":    "determining file type for processing",
		"extension": ext,
		"file_path": fb.filePath,
		"limit":     limit,
	}).Debug("detected file extension")

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
		log.WithError(err).WithFields(logger.Fields{
			"at":        "(FileBootstrap) processReseedFile",
			"phase":     "bootstrap",
			"reason":    "failed to process reseed file",
			"file_path": fb.filePath,
			"file_type": ext,
		}).Error("failed to process reseed file")
		return nil, err
	}

	return routerInfos, nil
}

// validateFile checks if the file exists and is readable
// checkFileAccessibility verifies that the file exists and is accessible.
// Returns os.FileInfo and nil if successful, or nil and an error if the file cannot be accessed.
func checkFileAccessibility(filePath string) (os.FileInfo, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.WithFields(logger.Fields{
				"at":         "(FileBootstrap) validateFile",
				"phase":      "bootstrap",
				"reason":     "reseed file does not exist",
				"file_path":  filePath,
				"suggestion": "verify file path or download reseed file",
			}).Warn("reseed file does not exist")
			return nil, fmt.Errorf("file bootstrap validation failed: file does not exist at path %s", filePath)
		}
		log.WithError(err).WithFields(logger.Fields{
			"at":         "(FileBootstrap) validateFile",
			"phase":      "bootstrap",
			"reason":     "failed to access reseed file",
			"file_path":  filePath,
			"error_type": fmt.Sprintf("%T", err),
		}).Warn("failed to stat reseed file")
		return nil, fmt.Errorf("file bootstrap validation failed: cannot access file %s: %w", filePath, err)
	}

	if info.IsDir() {
		log.WithFields(logger.Fields{
			"at":         "(FileBootstrap) validateFile",
			"phase":      "bootstrap",
			"reason":     "path is directory not file",
			"file_path":  filePath,
			"suggestion": "specify path to .su3 or .zip file, not directory",
		}).Warn("reseed path is a directory, not a file")
		return nil, fmt.Errorf("file bootstrap validation failed: path is a directory, not a file: %s", filePath)
	}

	return info, nil
}

// validateFileSize checks that the file is large enough to be a valid reseed file.
// Files smaller than 100 bytes are considered invalid.
func validateFileSize(filePath string, info os.FileInfo) error {
	if info.Size() < 100 {
		log.WithFields(logger.Fields{
			"at":         "(FileBootstrap) validateFile",
			"phase":      "bootstrap",
			"reason":     "file too small to be valid reseed",
			"file_path":  filePath,
			"size_bytes": info.Size(),
			"min_bytes":  100,
			"suggestion": "verify file is complete and not corrupted",
		}).Warn("reseed file is too small to be valid")
		return fmt.Errorf("file bootstrap validation failed: file too small (%d bytes) at %s", info.Size(), filePath)
	}
	return nil
}

func (fb *FileBootstrap) validateFile() error {
	log.WithFields(logger.Fields{
		"at":        "(FileBootstrap) validateFile",
		"phase":     "bootstrap",
		"reason":    "validating reseed file existence and accessibility",
		"file_path": fb.filePath,
	}).Debug("validating reseed file")

	if fb.filePath == "" {
		log.WithFields(logger.Fields{
			"at":     "(FileBootstrap) validateFile",
			"phase":  "bootstrap",
			"reason": "empty file path provided",
		}).Error("file bootstrap: empty file path provided")
		return fmt.Errorf("file bootstrap validation failed: empty file path")
	}

	info, err := checkFileAccessibility(fb.filePath)
	if err != nil {
		return err
	}

	if err := validateFileSize(fb.filePath, info); err != nil {
		return err
	}

	log.WithFields(logger.Fields{
		"file_path":  fb.filePath,
		"size_bytes": info.Size(),
	}).Debug("Reseed file validated successfully")

	return nil
}

// reseedProcessor is a function that processes a reseed file at filePath
// with the given limit and returns parsed RouterInfos.
type reseedProcessor func(filePath string, limit int) ([]router_info.RouterInfo, error)

// processReseedFileByType is the shared implementation for processSU3File and processZipFile.
// It logs, checks cancellation, invokes the type-specific processor, and finalizes results.
func (fb *FileBootstrap) processReseedFileByType(ctx context.Context, limit int, fileType string, process reseedProcessor) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"at":        "(FileBootstrap) process" + fileType + "File",
		"phase":     "bootstrap",
		"reason":    "processing " + fileType + " reseed file",
		"file_path": fb.filePath,
		"limit":     limit,
	}).Info("processing " + fileType + " reseed file")

	if ctx.Err() != nil {
		return nil, fmt.Errorf("file bootstrap canceled: %w", ctx.Err())
	}

	requestLimit := calculateRequestLimit(limit)
	routerInfos, err := process(fb.filePath, requestLimit)
	if err != nil {
		logReseedProcessingFailure("process"+fileType+"File", fileType, fb.filePath, err)
		return nil, fmt.Errorf("%s file processing failed for %s (requested %d peers): %w", fileType, fb.filePath, limit, err)
	}

	return fb.finalizeRouterInfos(routerInfos, limit, fileType)
}

// processSU3File reads and processes an SU3 reseed file with a limit on parsed RouterInfos.
// The limit parameter controls memory usage by stopping parse early when enough RouterInfos are obtained.
func (fb *FileBootstrap) processSU3File(ctx context.Context, limit int) ([]router_info.RouterInfo, error) {
	return fb.processReseedFileByType(ctx, limit, "SU3", func(filePath string, reqLimit int) ([]router_info.RouterInfo, error) {
		return reseed.NewReseed().ProcessLocalSU3FileWithLimit(filePath, reqLimit)
	})
}

// processZipFile reads and processes a zip reseed file with a limit on parsed RouterInfos.
// The limit parameter controls memory usage by stopping parse early when enough RouterInfos are obtained.
func (fb *FileBootstrap) processZipFile(ctx context.Context, limit int) ([]router_info.RouterInfo, error) {
	return fb.processReseedFileByType(ctx, limit, "ZIP", func(filePath string, reqLimit int) ([]router_info.RouterInfo, error) {
		return reseed.NewReseed().ProcessLocalZipFileWithLimit(filePath, reqLimit)
	})
}

// calculateRequestLimit doubles the limit to account for invalid RouterInfos during filtering.
// A limit of zero or less means no limit.
func calculateRequestLimit(limit int) int {
	if limit <= 0 {
		return 0
	}
	return limit * 2
}

// logReseedProcessingFailure logs an error when reseed file processing fails.
func logReseedProcessingFailure(funcName, fileType, filePath string, err error) {
	log.WithError(err).WithFields(logger.Fields{
		"at":        "(FileBootstrap) " + funcName,
		"phase":     "bootstrap",
		"reason":    fileType + " file processing failed",
		"file_path": filePath,
	}).Error("failed to process " + fileType + " file")
}

// finalizeRouterInfos validates, filters, and limits parsed RouterInfos.
// Returns an error if no valid RouterInfos remain after validation.
func (fb *FileBootstrap) finalizeRouterInfos(routerInfos []router_info.RouterInfo, limit int, fileType string) ([]router_info.RouterInfo, error) {
	validRouterInfos := fb.validateAndFilterRouterInfos(routerInfos, fileType)

	if len(validRouterInfos) == 0 {
		log.WithFields(logger.Fields{
			"at":        "(FileBootstrap) finalizeRouterInfos",
			"phase":     "bootstrap",
			"reason":    "no valid RouterInfos extracted after validation",
			"file_path": fb.filePath,
		}).Error("no valid RouterInfos extracted from " + fileType + " file")
		return nil, fmt.Errorf("%s file processing failed: no valid RouterInfos found in %s (file may be corrupted or contain invalid data)", fileType, fb.filePath)
	}

	if limit > 0 && len(validRouterInfos) > limit {
		validRouterInfos = validRouterInfos[:limit]
		log.WithFields(logger.Fields{
			"at":       "(FileBootstrap) finalizeRouterInfos",
			"phase":    "bootstrap",
			"reason":   "limiting valid RouterInfos to requested count",
			"limit":    limit,
			"returned": len(validRouterInfos),
		}).Debug("limited validated RouterInfos to requested count")
	}

	log.WithFields(logger.Fields{
		"at":           "(FileBootstrap) finalizeRouterInfos",
		"phase":        "bootstrap",
		"reason":       fileType + " processing completed successfully",
		"file_path":    fb.filePath,
		"router_count": len(validRouterInfos),
	}).Info("successfully processed " + fileType + " file")

	return validRouterInfos, nil
}

// validateAndFilterRouterInfos validates all RouterInfos and returns only valid ones.
// It also collects and logs statistics about the validation process.
func (fb *FileBootstrap) validateAndFilterRouterInfos(routerInfos []router_info.RouterInfo, fileType string) []router_info.RouterInfo {
	const caller = "(FileBootstrap) validateAndFilterRouterInfos"
	stats := NewValidationStats()
	validRouterInfos := make([]router_info.RouterInfo, 0, len(routerInfos))

	for _, ri := range routerInfos {
		if classifyRouterInfo(ri, stats, caller, fileType) {
			validRouterInfos = append(validRouterInfos, ri)
		}
	}

	stats.LogSummary(fmt.Sprintf("file_bootstrap_%s", fileType))
	logInvalidRouterInfos(stats, caller, fileType)

	return validRouterInfos
}
