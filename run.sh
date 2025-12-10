#! /usr/bin/env bash
go clean -cache
go build -v .
rm -f go-i2p.log ~/Downloads/i2preseed.zip
wget -O ~/Downloads/i2preseed.zip http://localhost:7657/createreseed
DEBUG_I2P=warn ./go-i2p --bootstrap.type file --bootstrap.reseed-file ~/Downloads/i2preseed.zip --i2cp.address localhost:8654 2>&1 | tee go-i2p.log
