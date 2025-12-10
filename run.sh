#! /usr/bin/env bash
if [ -z "$DEBUG_I2P" ]; then
    export DEBUG_I2P=warn
fi
rm -f go-i2p.log ~/Downloads/i2preseed.zip
go clean -cache
go build -v .
wget -O ~/Downloads/i2preseed.zip http://localhost:7657/createreseed
./go-i2p --bootstrap.type file --bootstrap.reseed-file ~/Downloads/i2preseed.zip --i2cp.address localhost:8654 2>&1 | tee go-i2p.log
