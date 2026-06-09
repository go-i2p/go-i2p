package nat

import "syscall"

// createReuseAddrControl returns a net.ListenConfig.Control function that sets
// SO_REUSEADDR on the socket. The logContext parameter customizes log messages
// (e.g., "probe TCP listener" vs "final UDP listener").
//
// SO_REUSEADDR allows binding to a port in TIME_WAIT state, reducing the TOCTOU
// race window when probing an OS-assigned port and then rebinding it.
//
// Thread-safe: Control functions are called once per socket creation.
func createReuseAddrControl(logContext string) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockoptErr error
		err := c.Control(func(fd uintptr) {
			if sockoptErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); sockoptErr != nil {
				log.WithError(sockoptErr).WithField("context", logContext).Warn("Failed to set SO_REUSEADDR")
			}
		})
		if err != nil {
			return err
		}
		return sockoptErr
	}
}
