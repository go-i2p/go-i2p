package data

import (
	"fmt"

	"github.com/samber/oops"
)

var (
	ErrZeroLength            = fmt.Errorf("error parsing string: zero length")
	ErrDataTooShort          = fmt.Errorf("string parsing warning: string data is shorter than specified by length")
	ErrDataTooLong           = fmt.Errorf("string parsing warning: string contains data beyond length")
	ErrLengthMismatch        = fmt.Errorf("error reading I2P string, length does not match data")
	ErrMappingLengthMismatch = fmt.Errorf("warning parsing mapping: mapping length exceeds provided data")
)

// WrapErrors compiles a slice of errors and returns them wrapped together as a single error.
func WrapErrors(errs []error) error {
	var err error
	for i, e := range errs {
		err = oops.Errorf("%v\n\t%d: %v", err, i, e)
	}
	return err
}

// PrintErrors prints a formatted list of errors to the console.
func PrintErrors(errs []error) {
	for i, e := range errs {
		fmt.Printf("\t%d: %v\n", i, e)
	}
}
