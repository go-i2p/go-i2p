// Package signals handles graceful shutdown of the go-i2p router in response
// to operating-system signals such as SIGTERM and SIGINT.
//
// # What is graceful shutdown?
//
// When a program is asked to stop — for example, when you press Ctrl+C
// (SIGINT) or the system sends a termination signal (SIGTERM) — it can either
// stop immediately or clean up first. Stopping immediately can leave the
// router in a bad state: tunnels not closed, the network database not saved,
// or other routers not told that this router is going offline.
//
// "Graceful shutdown" means the router notices the signal, then runs a set of
// cleanup steps in an orderly way before it exits.
//
// # How it works
//
// The package lets other parts of the router register cleanup work, and runs
// that work when a stop signal arrives.
//
//   - Pre-shutdown handlers. These run before the router stops. They are used
//     to announce to the network that the router is going offline — for
//     example, by publishing a database update with no addresses so other
//     routers stop trying to reach it. Handlers registered first run first
//     (FIFO order), and each runs under a timeout so one slow handler cannot
//     hang the shutdown.
//
//   - Reload and interrupt handlers. These let callers react to a reload
//     request (re-read configuration) or to the interrupt signal.
//
// [Handle] starts the signal listeners and blocks until a stop signal is
// received, then runs the registered handlers and returns.
//
// # Usage
//
//	// Register a handler that runs before the router shuts down.
//	id := signals.RegisterPreShutdownHandler(func() {
//		// Announce that this router is going offline.
//	})
//	defer signals.DeregisterPreShutdownHandler(id)
//
//	// Block until a stop signal arrives, then run cleanup.
//	signals.Handle()
//
// # Thread safety
//
// The exported registration functions are safe for concurrent use.
package signals
