module github.com/go-i2p/go-i2p

go 1.24.5

toolchain go1.24.11

require (
	github.com/beevik/ntp v1.5.0
	github.com/eyedeekay/go-unzip v0.0.0-20240201194209-560d8225b50e
	github.com/go-i2p/common v0.1.0
	github.com/go-i2p/crypto v0.1.0
	github.com/go-i2p/go-noise v0.0.3
	github.com/go-i2p/logger v0.1.0
	github.com/go-i2p/su3 v0.0.1
	github.com/samber/oops v1.19.4
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.21.0
	github.com/stretchr/testify v1.11.1
	go.step.sm/crypto v0.75.0
	golang.org/x/crypto v0.46.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-i2p/elgamal v0.0.2 // indirect
	github.com/go-i2p/noise v0.0.0-20250805205922-091c71f48c43 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/samber/lo v1.52.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.opentelemetry.io/otel v1.39.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
)

// Preserve these commented-out replace directives for local development.
// This makes it easier to test changes across multiple modules without needing to
// publish intermediate versions.

// Group 1: common, crypto, elgamal
//replace github.com/go-i2p/common => ../common

//replace github.com/go-i2p/crypto => ../crypto

// replace github.com/go-i2p/elgamal => ../elgamal

// Group 2: noise, go-noise
//replace github.com/go-i2p/noise => ../noise
//replace github.com/go-i2p/go-noise => ../go-noise

// Group 3: logger, su3
//replace github.com/go-i2p/logger => ../logger

//replace github.com/go-i2p/su3 => ../su3
