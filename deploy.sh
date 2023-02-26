#!/bin/bash

RG="playground-cose-eastus-rg"
FN_NAME="playground-cose-eastus-api"
env GOOS=linux GOARCH=arm64 go build -o bin/server server.go
zip -r deploy.zip .
az functionapp deployment source config-zip -g $RG -n $FN_NAME --src deploy.zip
