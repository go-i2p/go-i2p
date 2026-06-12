package transport

import "github.com/go-i2p/logger"

var log = logger.GetGoI2PLogger()

// logAt returns a logger.Entry with the "at" field pre-set to the given
// location string (typically the method name). This helper reduces boilerplate
// in log calls and ensures consistent "at" field formatting across the transport
// package. Usage: logAt("MethodName").Debug("message")
func logAt(at string) *logger.Entry {
	return log.WithFields(logger.Fields{"at": at})
}
