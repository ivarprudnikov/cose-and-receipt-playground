#!/bin/bash

# Build the binary for the current arch
rm -f bin/server
go build -o bin/server server.go
# Start Azure function
func start --verbose