package util

import (
	"os"
	"time"
)

// Check if a file exists and is readable etc
// returns false if not
func CheckFileExists(fpath string) bool {
	_, e := os.Stat(fpath)
	if e != nil {
		log.WithFields(map[string]interface{}{
			"at":   "CheckFileExists",
			"path": fpath,
		}).Debug("File does not exist")
	}
	return e == nil
}

// CheckFileAge checks if a file is older than maxAge minutes.
// Returns false if the file does not exist or on stat error.
// Returns true if file exists and its modification time is older than maxAge minutes.
func CheckFileAge(fpath string, maxAge int) bool {
	info, err := os.Stat(fpath)
	if err != nil {
		log.WithFields(map[string]interface{}{
			"at":   "CheckFileAge",
			"path": fpath,
		}).Debug("File does not exist for age check")
		// file does not exist, return false
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
