package util

import (
	"fmt"
)

// Panicf allows passing formated string to panic()
func Panicf(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	panic(s)
}
