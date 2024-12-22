#!/bin/bash

GOOS=js GOARCH=wasm go build -o  ../tests/assets/crypto.wasm
