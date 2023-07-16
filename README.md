Cose, receipt, did:web playground
=================================

[![Build](https://github.com/ivarprudnikov/cose-and-receipt-playground/actions/workflows/build.yml/badge.svg)](https://github.com/ivarprudnikov/cose-and-receipt-playground/actions/workflows/build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ivarprudnikov/cose-and-receipt-playground)](https://goreportcard.com/report/github.com/ivarprudnikov/cose-and-receipt-playground)

API/website: https://playground-cose-eastus-api.azurewebsites.net

# Development

**Prerequisites**

* Go
* Azure functions core tools

## Build and test

* build the binary `GOOS=linux GOARCH=amd64 go build -o bin/server server.go`
* run tests `go test -v ./...`

## Azure function

### Build and run locally

```sh
./scripts/run.sh
```

### Setup necessary resources

```
./deployments/azure.infra.create.sh
```

### Build and deploy (update)

```
./deployments/azure.fn.deploy.sh
```

# References

## Signatures and receipts

- CBOR Object Signing and Encryption (COSE): Structures and Process https://datatracker.ietf.org/doc/html/rfc9052
- CBOR Object Signing and Encryption (COSE): Countersignatures https://datatracker.ietf.org/doc/html/rfc9338 
- SCITT community https://github.com/scitt-community
- SCITT Architecture draft https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
- SCITT receipts https://datatracker.ietf.org/doc/draft-birkholz-scitt-receipts/

## Azure functions

- Create a Go function in Azure https://learn.microsoft.com/en-us/azure/azure-functions/create-first-function-vs-code-other
- Install and use Azure functions core tools https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local
- Wildcard routes in function config https://briandunnington.github.io/azure_functions_wildcard_routing
- Mount a file share in the function (Linux) https://learn.microsoft.com/en-us/azure/azure-functions/scripts/functions-cli-mount-files-storage-linux



wcbnkelmrn
rtber
ere



- Deploy a function with Azure CLI https://markheath.net/post/deploying-azure-functions-with-azure-cli 
