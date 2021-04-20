package util

import (
	"os"
)

// Check if a file exists and is readable etc
// returns false if not
func CheckFileExists(fpath string) bool {
	_, e := os.Stat(fpath)
	return e == nil
}
