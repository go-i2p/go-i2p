package data

import (
	"errors"
	"fmt"
)

var (
	ErrZeroLength            = errors.New("error parsing string: zero length")
	ErrDataTooShort          = errors.New("string parsing warning: string data is shorter than specified by length")
	ErrDataTooLong           = errors.New("string parsing warning: string contains data beyond length")
	ErrLengthMismatch        = errors.New("error reading I2P string, length does not match data")
	ErrMappingLengthMismatch = errors.New("warning parsing mapping: mapping length exceeds provided data")
)

// WrapErrors compiles a slice of errors and returns them wrapped together as a single error.
func WrapErrors(errs []error) error {
	var err error
	for i, e := range errs {
		err = fmt.Errorf("%v\n\t%d: %v", err, i, e)
	}
	return err
}

// PrintErrors prints a formatted list of errors to the console.
func PrintErrors(errs []error) {
	for i, e := range errs {
		fmt.Printf("\t%d: %v\n", i, e)
	}
}
