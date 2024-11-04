package ssu

/*
	Summary of what needs to be done:
	In addition to being a modified Noise protocol implementation,
	SSU2 also includes peer-testing features and QUIC-inspired features for resuming interrupted sessions.
	If we've done our jobs correctly when we get to this point, we will be implementing a net.Conn interface
	that can do the peer-testing and session management stuff, and we will **layer** it with our Noise protocol
	implementation and the SSU2 modifications.
*/