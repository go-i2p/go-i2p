Weekly notes about what I'm working on
======================================

July 18, 2022:

 - Implementation-in-Progress of a pure-Noise TCP transport using flynn/noise.
 - This transport is **not** operable with the rest of the I2P network and useful
 only for testing the transport interface implementation.
 - Most examples/docs on flynn/noise use client-server paradigm and not P2P paradigm, strictly
 speaking.
 - It does *not* process messages for obfuscation or de-obfuscation, key difference from NTCP2
 - It doesn't yet actually manage sending messages on a socket, right now it can:
  - Set up a Transport muxer
  - Set up a Transport, which is basically a session muxer sharing a common socket
  - Set up a Session, which is an individual connection to a peer which speaks the transport protocol
 - At some point there needs to be a loop on the socket which reads the socket for input and output.
 - At this time the transports *intentionally* do not know about the nature of the underlying socket 
 beyond the fact that it must implement a `net.Conn` interface so that it can connect over TCP.
 - In the future, this will need to be able to accept either a `net.Conn` or a `net.PacketConn`
