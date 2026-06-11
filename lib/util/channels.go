package util

// SingletonChan creates a buffered channel containing a single value.
// Useful for simple value returns wrapped in a channel for compatibility with
// channel-returning APIs. The channel is already closed, so receivers
// get the value immediately without blocking.
func SingletonChan[T any](value T) chan T {
	chnl := make(chan T, 1)
	chnl <- value
	close(chnl)
	return chnl
}

// ClosedChan creates an immediately closed channel that yields no values.
// Useful for error returns or empty-result cases in channel-returning APIs.
// Receivers doing <-chnl immediately get the zero value for T and the channel
// is already closed, so subsequent receives also return zero values.
func ClosedChan[T any]() chan T {
	chnl := make(chan T)
	close(chnl)
	return chnl
}
