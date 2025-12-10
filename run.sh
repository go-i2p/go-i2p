#! /usr/bin/env bash
if [ -z "$DEBUG_I2P" ]; then
    export DEBUG_I2P=warn
fi
rm -f go-i2p.log
go clean -cache
go build -v .
# Use existing reseed file or try to download a new one
if [ ! -f ~/Downloads/i2preseed.zip ] || [ ! -s ~/Downloads/i2preseed.zip ]; then
    echo "Attempting to download reseed file..."
    wget -O ~/Downloads/i2preseed.zip http://localhost:7657/createreseed 2>/dev/null || {
        echo "Failed to download reseed file, using existing i2pseeds.su3"
        RESEED_FILE=~/Downloads/i2pseeds.su3
    }
fi
# Set reseed file if not already set
: ${RESEED_FILE:=~/Downloads/i2preseed.zip}
./go-i2p --bootstrap.reseed-file "$RESEED_FILE" --i2cp.address localhost:8654 2>&1 | tee go-i2p.log
