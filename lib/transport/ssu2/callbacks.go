package ssu2

import (
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
)

// BlockCallbackConfig holds callback functions for SSU2 block types
// that require integration with higher-level router subsystems.
// These callbacks are wired into the go-noise/ssu2 DataHandler.
type BlockCallbackConfig struct {
	// OnTermination is called when a peer sends a Termination block (type 6).
	// validDataReceived is the number of valid data bytes received in this session;
	// reason is the termination reason code; additionalData carries optional extended data.
	OnTermination func(validDataReceived uint64, reason uint8, additionalData []byte)

	// OnRouterInfo is called when a RouterInfo block (type 2) is received.
	// The data should be forwarded to the NetDB subsystem.
	OnRouterInfo func(data []byte) error

	// OnACK is called when an ACK block (type 12) is received.
	OnACK func(block *ssu2noise.SSU2Block) error

	// OnDateTime is called when a DateTime block (type 0) is received.
	OnDateTime func(timestamp uint32) error

	// OnPeerTest is called when a PeerTest block (type 10) is received.
	OnPeerTest func(block *ssu2noise.SSU2Block) error

	// OnRelayRequest is called when a RelayRequest block (type 7) is received.
	OnRelayRequest func(block *ssu2noise.SSU2Block) error

	// OnRelayResponse is called when a RelayResponse block (type 8) is received.
	OnRelayResponse func(block *ssu2noise.SSU2Block) error

	// OnRelayIntro is called when a RelayIntro block (type 9) is received.
	OnRelayIntro func(block *ssu2noise.SSU2Block) error

	// OnNewToken is called when a NewToken block (type 17) is received.
	OnNewToken func(token []byte)

	// OnAddress is called when an Address block (type 13) is received.
	OnAddress func(data []byte) error

	// OnOptions is called when an Options block (type 1) is received.
	OnOptions func(data []byte) error

	// OnPathChallenge is called when a PathChallenge block (type 18) is received.
	OnPathChallenge func(data []byte) error

	// OnPathResponse is called when a PathResponse block (type 19) is received.
	OnPathResponse func(data []byte) error
}

// ToDataHandlerCallbacks converts BlockCallbackConfig into go-noise/ssu2
// DataHandlerCallbacks for wiring into the DataHandler.
// OnTermination is applied first; then all remaining non-nil callbacks are
// merged via mergeBlockCallbacks (shared with session.go) to avoid duplication.
func (c *BlockCallbackConfig) ToDataHandlerCallbacks() ssu2noise.DataHandlerCallbacks {
	cbs := ssu2noise.DataHandlerCallbacks{}
	if c.OnTermination != nil {
		cbs.OnTermination = c.OnTermination
	}
	mergeBlockCallbacks(&cbs, c)
	return cbs
}

// DefaultBlockCallbacks returns a BlockCallbackConfig with logging-only
// defaults for all block types. Production code should override callbacks
// for block types that need real handling.
func DefaultBlockCallbacks() *BlockCallbackConfig {
	return &BlockCallbackConfig{
		OnTermination: func(_ uint64, reason uint8, _ []byte) {
			log.WithField("reason", reason).Info("Received SSU2 termination block")
		},
		OnRouterInfo: func(_ []byte) error {
			log.Debug("Received RouterInfo block (not yet wired to NetDB)")
			return nil
		},
		OnDateTime: func(timestamp uint32) error {
			log.WithField("timestamp", timestamp).Debug("Received DateTime block")
			return nil
		},
	}
}
