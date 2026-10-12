// Package reseed downloads and installs the I2P network database (NetDB)
// from trusted reseed servers, so a new router can bootstrap its view of the
// network.
//
// # What is reseed?
//
// When an I2P router starts for the first time, it does not yet know about
// any other routers. To join the network it needs a starting list of routers
// to talk to. That list is the NetDB (network database).
//
// "Reseed" is the process of downloading a fresh copy of the NetDB from a
// trusted reseed server. A reseed server is a well-known I2P router that
// publishes a snapshot of the current network.
//
// # How it works
//
// The NetDB is distributed as an SU3 file — a ZIP-based archive that bundles
// the network database together with a signature so the router can verify it
// came from a trusted source. The standard file name is "i2pseeds.su3".
//
// The [Reseed] type performs the download:
//
//   - It connects to a reseed server over HTTP or HTTPS.
//   - It downloads the SU3 file.
//   - It verifies the file's signature against a trusted certificate.
//   - It extracts the NetDB entries and hands them to the router.
//
// For HTTPS, the package verifies the server's TLS certificate against a
// certificate pool. See [GetDefaultCertificatePool] and
// [NewCertificatePoolFromFS] for how that pool is built.
//
// The package can also install a NetDB from a local SU3 file, which is useful
// for offline or air-gapped setups. See [ProcessLocalSU3File].
//
// See the I2P reseed documentation for the broader reseed process:
// https://github.com/i2p/i2p.www/blob/master/i2p2www/pages/site/docs/reseed.html
//
// # Usage
//
//	// Download the NetDB from a single reseed server.
//	reseeder := reseed.NewReseed()
//	routerInfos, err := reseeder.SingleReseed("https://reseed.example.net/i2pseeds.su3")
//	if err != nil {
//		log.Fatal(err)
//	}
//	// routerInfos holds the routers to seed the NetDB with.
//
// # Thread safety
//
// A [Reseed] value holds a shared HTTP client with connection pooling. It is
// safe to use a single [Reseed] value from multiple goroutines.
package reseed
