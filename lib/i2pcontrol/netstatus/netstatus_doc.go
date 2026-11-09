// Package netstatus defines the I2PControl network status codes and their
// canonical names.
//
// The codes are part of the I2PControl wire protocol: a router reports one as
// i2p.router.status and i2p.router.net.status, and every component that
// produces, forwards or interprets that number needs the same vocabulary.
// lib/i2pcontrol cannot be imported by the packages that report the code —
// lib/transport/ssu2 and lib/tui both sit below it in the dependency order — so
// the codes live here, in a leaf package with no dependencies, and each consumer
// aliases what it needs.
package netstatus
