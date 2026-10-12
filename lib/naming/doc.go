// Package naming provides hostname resolution for I2P destinations.
//
// # What is naming?
//
// I2P destinations are identified by long base64 strings, which are hard for
// people to type. Naming maps friendly .i2p hostnames (for example,
// "forum.i2p") to their underlying destination, so applications can look up a
// destination by name.
//
// The default implementation uses an embedded hosts.txt file from the Java I2P
// router distribution, which maps .i2p hostnames to their base64-encoded
// Destination representations.
package naming
