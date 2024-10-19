// Package session_key implements the I2P SessionKey common data structure
package session_key

import log "github.com/sirupsen/logrus"

/*
[SessionKey]
Accurate for version 0.9.49

Description
This structure is used for symmetric AES256 encryption and decryption.

Contents
32 bytes
*/

// SessionKey is the represenation of an I2P SessionKey.
//
// https://geti2p.net/spec/common-structures#sessionkey
type SessionKey [32]byte

// ReadSessionKey returns SessionKey from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadSessionKey(bytes []byte) (info SessionKey, remainder []byte, err error) {
	// TODO: stub
	log.Warn("ReadSessionKey is not implemented")
	return
}

// NewSessionKey creates a new *SessionKey from []byte using ReadSessionKey.
// Returns a pointer to SessionKey unlike ReadSessionKey.
func NewSessionKey(data []byte) (session_key *SessionKey, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Creating new SessionKey")
	sessionKey, remainder, err := ReadSessionKey(data)
	if err != nil {
		log.WithError(err).Error("Failed to create new SessionKey")
		return nil, remainder, err
	}
	session_key = &sessionKey
	log.Debug("Successfully created new SessionKey")
	return
}
