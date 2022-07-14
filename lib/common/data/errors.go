package data

import "fmt"

// Sometimes we recieve a whole list of errors from a compound operation
// like constructing a Map. We want to print them all out so we can see
// what's wrong.
func WrapErrors(errs []error) error {
	var err error
	for i, e := range errs {
		err = fmt.Errorf("%v\n\t%d: %v", err, i, e)
	}
	return err
}

// Prints a list of errors to the console.
func PrintErrors(errs []error) {
	for i, e := range errs {
		fmt.Printf("\t%d: %v\n", i, e)
	}
}
