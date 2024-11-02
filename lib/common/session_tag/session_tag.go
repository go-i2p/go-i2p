// Package session_tag implements the I2P SessionTag common data structure
package session_tag

import (
	"github.com/go-i2p/go-i2p/lib/util/logger"
	"github.com/sirupsen/logrus"
)

var log = logger.GetGoI2PLogger()

/*
[SessionKey]
Accurate for version 0.9.49

Description
A random number

Contents
32 bytes
*/

// SessionTag is the represenation of an I2P SessionTag.
//
// https://geti2p.net/spec/common-structures#session-tag
type SessionTag [32]byte

// ReadSessionTag returns SessionTag from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadSessionTag(bytes []byte) (info SessionTag, remainder []byte, err error) {
	// TODO: stub
	log.Warn("ReadSessionTag is not implemented")
	return
}

// NewSessionTag creates a new *SessionTag from []byte using ReadSessionTag.
// Returns a pointer to SessionTag unlike ReadSessionTag.
func NewSessionTag(data []byte) (session_tag *SessionTag, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Creating new SessionTag")
	sessionTag, remainder, err := ReadSessionTag(data)
	if err != nil {
		log.WithError(err).Error("Failed to read SessionTag")
		return nil, remainder, err
	}
	session_tag = &sessionTag
	log.WithFields(logrus.Fields{
		"remainder_length": len(remainder),
	}).Debug("Successfully created new SessionTag")
	return
}
