package util

import (
	"os"
	"time"
)

// Check if a file exists and is readable etc
// returns false if not
func CheckFileExists(fpath string) bool {
	_, e := os.Stat(fpath)
	return e == nil
}

// CheckFileAge checks if a file is older than maxAge minutes.
// Returns false if the file does not exist or on stat error.
// Returns true if file exists and its modification time is older than maxAge minutes.
func CheckFileAge(fpath string, maxAge int) bool {
	info, err := os.Stat(fpath)
	if err != nil {
		// file does not exist, return false
		return false
	}
	xMinAgo := time.Now().Add(time.Duration(-maxAge) * time.Minute)
	// Exists and is older than age, return true
	return info.ModTime().Before(xMinAgo)
}
