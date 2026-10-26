package ssu2

// Maximum plaintext I2NP payload per SSU2 packet, by IP family.
//
//	IPv4: 1472 (max wire) - 16 (short header) - 16 (MAC placeholder) - 16 (AEAD tag) = 1424
//	IPv6: 1452 (max wire) - 16 (short header) - 16 (MAC placeholder) - 16 (AEAD tag) = 1404
//
// The fragmentation itself lives in fragmentSSU2Short (session.go), which
// implements the spec's FirstFragment / FollowOnFragment wire formats. The
// previous, self-documented non-standard fragment encoder that used to live in
// this file was dead: no live path called it, and the conformant path
// (sendWithCongestionControl -> fragmentSSU2Short) replaced it.
const (
	maxSSU2PayloadIPv4 = 1424
	maxSSU2PayloadIPv6 = 1404
)
