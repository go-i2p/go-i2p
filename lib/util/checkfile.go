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

// Check if a file is more than maxAge minutes old
// returns false if
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
