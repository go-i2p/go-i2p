package data

import "fmt"

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
