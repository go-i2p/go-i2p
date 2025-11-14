module github.com/go-i2p/go-i2p

go 1.24.4

require (
	github.com/beevik/ntp v1.4.3
	github.com/eyedeekay/go-unzip v0.0.0-20240201194209-560d8225b50e
	github.com/go-i2p/common v0.0.2
	github.com/go-i2p/crypto v0.0.2
	github.com/go-i2p/go-noise v0.0.1
	github.com/go-i2p/logger v0.0.1
	github.com/go-i2p/su3 v0.0.1
	github.com/samber/oops v1.19.3
	github.com/spf13/cobra v1.9.1
	github.com/spf13/viper v1.20.1
	github.com/stretchr/testify v1.11.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
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
	github.com/sagikazarmark/locafero v0.10.0 // indirect
	github.com/samber/lo v1.52.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.14.0 // indirect
	github.com/spf13/cast v1.9.2 // indirect
	github.com/spf13/pflag v1.0.7 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.step.sm/crypto v0.67.0 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/net v0.45.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/text v0.30.0 // indirect
)

// Preserve these commented-out replace directives for local development.
// This makes it easier to test changes across multiple modules without needing to
// publish intermediate versions.

// Group 1: common, crypto, elgamal
//replace github.com/go-i2p/common => ../common
//replace github.com/go-i2p/crypto => ../crypto
//replace github.com/go-i2p/elgamal => ../elgamal

// Group 2: noise, go-noise
//replace github.com/go-i2p/noise => ../noise
//replace github.com/go-i2p/go-noise => ../go-noise
