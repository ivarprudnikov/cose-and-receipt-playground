Cose, receipt, did:web playground
=================================

API/website: https://playground-cose-eastus-api.azurewebsites.net

# Development

**Prerequisites**

* Go
* Azure functions core tools

## Run locally

```sh
./run.sh
```

## Build and deploy

```
./deploy.sh
```

# References

- Create a Go function in Azure https://learn.microsoft.com/en-us/azure/azure-functions/create-first-function-vs-code-other
- Install and use Azure functions core tools https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local
- Wildcard routes in function config https://briandunnington.github.io/azure_functions_wildcard_routing
- Mount a file share in the function (Linux) https://learn.microsoft.com/en-us/azure/azure-functions/scripts/functions-cli-mount-files-storage-linux
- Deploy a function with Azure CLI https://markheath.net/post/deploying-azure-functions-with-azure-cli 