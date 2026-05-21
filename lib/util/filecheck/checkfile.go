package filecheck

import (
	"errors"
	"os"
	"time"
)

// CheckFileExists checks if a file exists and is readable.
// Returns false if not.
func CheckFileExists(fpath string) bool {
	_, e := os.Stat(fpath)
	if e != nil {
		if os.IsNotExist(e) {
			log.WithFields(map[string]interface{}{
				"at":   "CheckFileExists",
				"path": fpath,
			}).Debug("File does not exist")
		} else {
			log.WithFields(map[string]interface{}{
				"at":    "CheckFileExists",
				"path":  fpath,
				"error": e.Error(),
			}).Warn("Failed to stat file (permission denied or I/O error)")
		}
	}
	return e == nil
}

// CheckFileAge checks if a file is older than maxAge minutes.
// Returns false if the file does not exist, on stat error, or if maxAge is negative.
// Returns true if file exists and its modification time is older than maxAge minutes.
func CheckFileAge(fpath string, maxAge int) bool {
	if maxAge < 0 {
		log.WithFields(map[string]interface{}{
			"at":      "CheckFileAge",
			"path":    fpath,
			"max_age": maxAge,
		}).Warn("negative maxAge is invalid, returning false")
		return false
	}
	info, err := os.Stat(fpath)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			log.WithFields(map[string]interface{}{
				"at":   "CheckFileAge",
				"path": fpath,
			}).Debug("File does not exist for age check")
		case errors.Is(err, os.ErrPermission):
			log.WithFields(map[string]interface{}{
				"at":    "CheckFileAge",
				"path":  fpath,
				"error": err.Error(),
			}).Warn("Permission denied reading file for age check")
		default:
			log.WithFields(map[string]interface{}{
				"at":    "CheckFileAge",
				"path":  fpath,
				"error": err.Error(),
			}).Warn("Failed to stat file for age check")
		}
		return false
	}
	xMinAgo := time.Now().Add(time.Duration(-maxAge) * time.Minute)
	isOld := info.ModTime().Before(xMinAgo)
	log.WithFields(map[string]interface{}{
		"at":      "CheckFileAge",
		"path":    fpath,
		"max_age": maxAge,
		"is_old":  isOld,
	}).Debug("File age checked")
	// Exists and is older than age, return true
	return isOld
}
