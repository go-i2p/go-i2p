module github.com/go-i2p/go-i2p

go 1.26.1

require (
	github.com/beevik/ntp v1.5.0
	github.com/charmbracelet/bubbletea v1.3.10
	github.com/charmbracelet/lipgloss v1.1.0
	github.com/go-i2p/common v0.1.4-0.20260406221321-5d52c2809acd
	github.com/go-i2p/crypto v0.1.4-0.20260327201310-96101c044a62
	github.com/go-i2p/go-nat-listener v0.0.0-20260402222111-bfda0025cb1b
	github.com/go-i2p/go-noise v0.1.4-0.20260406215923-93b02ff49d4f
	github.com/go-i2p/go-unzip v0.0.0-20260417162122-21146ed7aca8
	github.com/go-i2p/i2ptui v0.0.0-20260408024448-18dc7a0919f8
	github.com/go-i2p/logger v0.1.5
	github.com/go-i2p/su3 v0.0.2-0.20260406203134-0ec837609b00
	github.com/samber/oops v1.21.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.21.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.50.0
	golang.org/x/time v0.15.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/bubbles v1.0.0 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/x/ansi v0.11.7 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-i2p/elgamal v0.0.2 // indirect
	github.com/go-i2p/go-i2pcontrol v0.1.8 // indirect
	github.com/go-i2p/noise v1.1.1-0.20260327201800-8e41bb3d9f1e // indirect
	github.com/go-i2p/red25519 v0.0.0-20260302212615-1093a31f680d // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.23 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/pelletier/go-toml/v2 v2.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/samber/lo v1.53.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/ybbus/jsonrpc/v2 v2.1.7 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	go.step.sm/crypto v0.77.2 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
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

//replace github.com/go-i2p/go-nat-listener => ../go-nat-listener
