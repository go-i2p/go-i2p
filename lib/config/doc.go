// Package config provides configuration management for go-i2p router.
//
// # Configuration Directories
//
// BaseDir vs WorkingDir: This router uses two separate directory paths to distinguish
// between read-only system defaults and mutable runtime state:
//
// BaseDir: Contains read-only default configuration files that ship with the system.
// These files provide fallback values and should not be modified during runtime. When
// you want to customize the configuration, copy the relevant files from BaseDir to
// WorkingDir and edit them there.
//   - Default location: $HOME/.go-i2p/base
//   - Purpose: System-wide defaults, pristine copies of configuration templates
//   - Examples: Default router.config, reseed certificates, bootstrap RouterInfo
//
// WorkingDir: Contains runtime-modifiable configuration files and state. The router
// reads from WorkingDir first, falling back to BaseDir if a file doesn't exist. All
// runtime changes (e.g., adding peers, updating configuration) are written here.
//   - Default location: $HOME/.go-i2p/config
//   - Purpose: User customizations, runtime state, active NetDB
//   - Examples: Custom router.config overrides, netDb directory, active LeaseSet cache
//
// Usage Pattern: To customize a configuration option, copy the file from BaseDir to
// WorkingDir, then edit the copy in WorkingDir. The router will automatically prefer
// the WorkingDir version while preserving the BaseDir original.
package config
