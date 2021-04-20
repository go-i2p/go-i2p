package util

import "io"

var closeOnExit []io.Closer

func RegisterCloser(c io.Closer) {
	closeOnExit = append(closeOnExit, c)
}

func CloseAll() {
	for idx := range closeOnExit {
		closeOnExit[idx].Close()
	}
	closeOnExit = nil
}
