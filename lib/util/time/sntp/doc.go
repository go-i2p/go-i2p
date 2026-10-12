// Package sntp provides the router's clock source, keeping the local system
// time accurate by querying Network Time Protocol (NTP) servers.
//
// # Why does the router need accurate time?
//
// I2P relies on timestamps in several places: deciding which router
// information is still fresh, ordering events, and validating messages. If
// the router's clock is far off, it may reject valid data or accept stale
// data. So the router keeps its clock in sync with trusted time servers.
//
// # What is NTP?
//
// NTP (Network Time Protocol) is a standard protocol for synchronizing clocks
// over the network. A client asks a time server "what time is it?" and
// adjusts its own clock to match. This package uses NTP to keep the router's
// time correct.
//
// # How it works
//
// The [RouterTimestamper] is the main type. It periodically queries NTP
// servers and, when the time changes, notifies registered listeners so the
// rest of the router can react.
//
//   - The [NTPClient] interface abstracts the actual NTP query, so the
//     underlying NTP implementation can be swapped. [DefaultNTPClient] is the
//     built-in client.
//
//   - Listeners. An [UpdateListener] is called whenever the time is updated.
//     An [ExtendedUpdateListener] additionally receives the detected timezone
//     and country, which the package determines from the NTP server's
//     location.
//
// # Usage
//
//	// Create a timestamper using the default NTP client.
//	timestamper := sntp.NewRouterTimestamper(&sntp.DefaultNTPClient{})
//
// # Thread safety
//
// A [RouterTimestamper] is safe for concurrent use.
package sntp
