Cose, receipt, did:web playground
=================================

[![Build](https://github.com/ivarprudnikov/cose-and-receipt-playground/actions/workflows/build.yml/badge.svg)](https://github.com/ivarprudnikov/cose-and-receipt-playground/actions/workflows/build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ivarprudnikov/cose-and-receipt-playground)](https://goreportcard.com/report/github.com/ivarprudnikov/cose-and-receipt-playground)

API/website: https://playground-cose-eastus-api.azurewebsites.net

# Development

**Prerequisites**

- Install Go to compile and run the application: https://golang.org/doc/install
- Install Node to run e2e tests: https://nodejs.org/en/download/
- Install Azure Functions Core Tools if you will run the local in Azure functions environment: https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local
- Access to Azure if you will create/update/deploy function app: https://portal.azure.com
  - Azure CLI is used when deploying the [resources](./deployments/)

**Commands**

- Testing
  - Run unit tests: `go test -v ./...`
  - Run functional end-to-end (e2e) tests, [see readme](cypress/README.md)
- Running locally
  - Compile and execute the server binary: `go run .`
  - Or, run the server in an Azure function environment locally: `./scripts/run.sh`
- Deployment
  - Build the binary `GOOS=linux GOARCH=amd64 go build -o bin/server server.go`
  - Compile and deploy to Azure: [azure.fn.deploy.sh](deployments/azure.fn.deploy.sh)
  - Create required Azure infrastructure: [azure.infra.create.sh](deployments/azure.infra.create.sh)

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
- Deploy a function with Azure CLI https://markheath.net/post/deploying-azure-functions-with-azure-cli 