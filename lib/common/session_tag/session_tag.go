// Package session_tag implements the I2P SessionTag common data structure
package session_tag

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
	return
}

// NewSessionTag creates a new *SessionTag from []byte using ReadSessionTag.
// Returns a pointer to SessionTag unlike ReadSessionTag.
func NewSessionTag(data []byte) (session_tag *SessionTag, remainder []byte, err error) {
	sessionTag, remainder, err := ReadSessionTag(data)
	session_tag = &sessionTag
	return
}
