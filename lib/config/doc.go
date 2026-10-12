// Package config provides configuration management for the go-i2p router.
//
// # What is config?
//
// A router has many settings: which ports to listen on, how many tunnels to
// build, which peers to trust, and so on. This package loads those settings,
// fills in sensible defaults for anything the user did not set, and exposes
// them to the rest of the router.
//
// # Two directories: defaults vs. your changes
//
// The router keeps its files in two separate directories so that the
// built-in defaults are never overwritten by your changes:
//
//   - BaseDir holds read-only default files that ship with the system. They
//     provide fallback values and should not be edited.
//     Default location: $HOME/.go-i2p/base.
//     Examples: the default router.config, reseed certificates, bootstrap
//     RouterInfo.
//
//   - WorkingDir holds your customizations and runtime state. The router
//     reads from WorkingDir first and falls back to BaseDir only when a file
//     is missing. All runtime changes (adding peers, updating settings) are
//     written here.
//     Default location: $HOME/.go-i2p/config.
//     Examples: your router.config overrides, the netDb directory, the active
//     LeaseSet cache.
//
// To customize a setting, copy the file from BaseDir to WorkingDir and edit
// the copy. The router always prefers the WorkingDir version while leaving
// the BaseDir original untouched.
//
// # Usage
//
//	// Load the router configuration, applying defaults for anything unset.
//	cfg, err := config.NewRouterConfigFromViper()
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Thread safety
//
// A loaded [RouterConfig] is not safe for concurrent mutation. Load it once
// at startup and treat it as read-only while the router runs.
package config
