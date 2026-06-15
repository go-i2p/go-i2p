package transport

import (
	"net"
	"sync"
)

// ipv6Once ensures the IPv6 connectivity probe runs exactly once per process.
var (
	ipv6Once       sync.Once
	hasIPv6Support bool
)

// hasGlobalUnicastIPv6OnIface returns true if the given network interface has
// at least one globally reachable IPv6 address.
func hasGlobalUnicastIPv6OnIface(iface net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.To4() == nil && ip.IsGlobalUnicast() {
			return true
		}
	}
	return false
}

// ProbeIPv6 returns true if the host has at least one non-loopback, globally
// unicast IPv6 interface. The result is cached after the first call.
func ProbeIPv6() bool {
	ipv6Once.Do(func() {
		ifaces, err := net.Interfaces()
		if err != nil {
			return
		}
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if hasGlobalUnicastIPv6OnIface(iface) {
				hasIPv6Support = true
				return
			}
		}
	})
	return hasIPv6Support
}
