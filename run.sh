#! /usr/bin/env bash
go build -v .
DEBUG_I2P=debug ./go-i2p --bootstrap.type file --bootstrap.reseed-file ~/i2p/i2preseed.zip --i2cp.address localhost:8654 2>&1 | tee go-i2p.log
