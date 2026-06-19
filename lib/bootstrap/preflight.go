package bootstrap

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-i2p/logger"
)

// TestNetworkConnectivity performs basic network connectivity checks at startup.
// It validates that the router has external network access by testing DNS
// resolution and TCP connectivity to reseed hosts.
//
// Returns error if network connectivity cannot be established to any test host.
// This is a non-blocking preflight check; a failure does not prevent router startup,
// but may be logged as a warning.
func TestNetworkConnectivity() error {
	log.WithFields(logger.Fields{
		"at":     "TestNetworkConnectivity",
		"phase":  "startup",
		"reason": "validating external network access",
	}).Info("running network connectivity pre-check")

	if err := TestDNSResolution(); err != nil {
		return err
	}

	if err := TestTCPConnectivity(); err != nil {
		return err
	}

	log.WithFields(logger.Fields{
		"at":     "TestNetworkConnectivity",
		"phase":  "startup",
		"result": "success",
	}).Info("Network connectivity pre-check passed - external access confirmed")

	return nil
}

// TestDNSResolution verifies DNS resolution works for reseed hosts.
func TestDNSResolution() error {
	log.Debug("Testing DNS resolution...")
	testHosts := []string{
		"reseed.i2pgit.org",
	}

	for _, host := range testHosts {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resolver := &net.Resolver{}
		addrs, err := resolver.LookupHost(ctx, host)
		cancel()
		if err != nil {
			log.WithFields(logger.Fields{
				"host":  host,
				"error": err.Error(),
			}).Warn("DNS lookup failed for reseed host")
			continue
		}
		log.WithFields(logger.Fields{
			"host":       host,
			"resolved":   len(addrs),
			"first_addr": addrs[0],
		}).Debug("DNS resolution successful")
		log.Infof("DNS resolution successful: %s -> %s", host, addrs[0])
		return nil
	}

	return fmt.Errorf("DNS resolution failed for all test hosts - check network/DNS configuration")
}

// TestTCPConnectivity verifies TCP connectivity to reseed servers.
func TestTCPConnectivity() error {
	log.Debug("Testing TCP connectivity to reseed server...")
	tcpTestHosts := []string{
		"reseed.i2pgit.org:443",
	}

	for _, hostPort := range tcpTestHosts {
		log.Infof("Testing TCP connection to %s...", hostPort)
		conn, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
		if err != nil {
			log.WithFields(logger.Fields{
				"target": hostPort,
				"error":  err.Error(),
			}).Warn("TCP connectivity test failed")
			log.Warnf("TCP connectivity test failed to %s: %v", hostPort, err)
			continue
		}
		conn.Close()
		log.WithFields(logger.Fields{
			"target": hostPort,
		}).Debug("TCP connectivity test successful")
		log.Infof("TCP connectivity test successful to %s", hostPort)
		return nil
	}

	return fmt.Errorf("TCP connectivity failed to all test hosts - check firewall/network configuration")
}
