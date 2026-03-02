<!--
---
name: NVD MCP Server (Azure Functions — Python)
description: A remote MCP server that exposes the NIST National Vulnerability Database (NVD) REST APIs as MCP tools, hosted on Azure Functions.
page_type: sample
languages:
- python
- bicep
- azdeveloper
products:
- azure-functions
- azure-keyvault
- azure
---
-->

# NVD MCP Server — Azure Functions (Python)

A remote [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server that exposes the [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/) APIs as AI-callable tools. Built on Azure Functions with Python, deployed via `azd`.

The NVD API key is **optional** — the server works without one at a lower rate limit (5 req/30s unauthenticated vs 50 req/30s authenticated). Get a free key at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

## Available MCP Tools

| Tool | Description |
|---|---|
| `search_cves` | Search the CVE database by keyword, severity, CWE, CPE, date ranges, KEV membership, and more |
| `get_cve` | Retrieve full details for a specific CVE (CVSS scores, affected configurations, references) |
| `get_cve_history` | Get the change history for CVEs, filterable by date range and event type |

## Quickstart — GitHub Codespaces (zero local install)

The repo includes a pre-configured dev container that has all tools installed automatically (Python, azd, az, func, Node, Azurite, MCP Inspector).

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/KnowledgeRatio/nvd-mcp-func)

Or open locally in VS Code:

1. Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
2. Clone the repo and open it in VS Code
3. When prompted, click **Reopen in Container**

Everything in the [Run locally](#run-locally) and [Deploy to Azure](#deploy-to-azure) sections will work inside the container without installing anything on your machine.

---

## Prerequisites

- [Python](https://www.python.org/downloads/) 3.11 or higher
- [Azure Functions Core Tools](https://learn.microsoft.com/azure/azure-functions/functions-run-local) >= `4.0.7030`
- [Azure Developer CLI (`azd`)](https://aka.ms/azd)
- [Azure CLI (`az`)](https://learn.microsoft.com/cli/azure/install-azure-cli)
- [Node.js](https://nodejs.org/) (for Azurite local storage emulator)
- VS Code + [Azure Functions extension](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azurefunctions) (optional)

### Installing prerequisites on macOS

The easiest way is via [Homebrew](https://brew.sh/):

```shell
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install tools
brew install azure-developer-cli
brew install azure-cli
brew tap azure/functions
brew install azure-functions-core-tools@4
brew install node
```

### Installing prerequisites on Windows

```shell
winget install Microsoft.Azd
winget install Microsoft.AzureCLI
npm install -g azure-functions-core-tools@4 --unsafe-perm true
```

## Run locally

### 1. Start the storage emulator

```shell
npx azurite --location ~/.azurite --silent
```

### 2. Create a virtual environment and install dependencies

```shell
cd src
python -m venv .venv

# Windows
.venv\Scripts\pip install -r requirements.txt

# macOS / Linux
.venv/bin/pip install -r requirements.txt
```

### 3. Configure local settings

```shell
cp src/local.settings.json.example src/local.settings.json
```

Edit `src/local.settings.json` and optionally fill in your NVD API key:

```json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "PYTHON_ISOLATE_WORKER_DEPENDENCIES": "1",
    "NVD_API_KEY": "<your-key-or-leave-empty>"
  }
}
```

> **Note:** `local.settings.json` is gitignored and will never be committed.

### 4. Start the Functions host

```shell
cd src
func start
```

The MCP server will be available at `http://localhost:7071/runtime/webhooks/mcp`.

## Connect from a client

### VS Code — GitHub Copilot agent mode

Open `.vscode/mcp.json`. Click **Start** above the `local-mcp-function` server entry. Then ask Copilot:

```
Search for critical CVEs related to log4j
```

```
Get the full details for CVE-2021-44228
```

### MCP Inspector

```shell
npx @modelcontextprotocol/inspector
```

Set transport to `Streamable HTTP`, URL to `http://localhost:7071/runtime/webhooks/mcp`, and click **Connect**.

## Deploy to Azure

### 1. Log in to Azure

```shell
azd auth login
```

### 2. Create an azd environment

```shell
azd env new <your-environment-name>
```

### 3. Set required environment variables

```shell
# Required: choose a supported region (see infra/main.bicep for the full allowed list)
azd env set AZURE_LOCATION <region>   # e.g. uksouth, swedencentral, eastus

# Required: set to true to deploy with VNet + private endpoints, false for public access
azd env set VNET_ENABLED false
```

> **Multiple subscriptions?** If your account has more than one subscription, also run:
> ```shell
> azd env set AZURE_SUBSCRIPTION_ID <your-subscription-id>
> ```

### 4. (Optional) Set your NVD API key

```shell
azd env set NVD_API_KEY <your-key>
```

If you skip this step, the server deploys and works unauthenticated. You can add the key later.

### 5. Deploy

```shell
azd up
```

This provisions a resource group containing:
- Azure Functions app (Flex Consumption plan)
- Azure Key Vault (stores the NVD API key if provided)
- Azure Storage account
- Application Insights + Log Analytics workspace
- User-assigned managed identity

### 6. Connect to the remote MCP server

Get the system key for your deployed endpoint:

```shell
az functionapp keys list \
  --name <function-app-name> \
  --resource-group <resource-group> \
  --query "systemKeys.mcp_extension" -o tsv
```

Your endpoint: `https://<funcappname>.azurewebsites.net/runtime/webhooks/mcp`

In VS Code, click **Start** on the `remote-mcp-function` entry in `.vscode/mcp.json` — it will prompt for the function app name and system key.

### Update the NVD API key after deployment

```shell
az keyvault secret set \
  --vault-name <keyvault-name> \
  --name NVD-API-KEY \
  --value <new-key>
```

The Function App resolves the Key Vault reference automatically on next invocation (cached up to ~24h; restart the app for immediate effect).

## Secrets management

| Context | How the key is stored |
|---|---|
| Local | `src/local.settings.json` (gitignored) |
| Azure | Azure Key Vault secret; Function App reads it at runtime via a Key Vault reference using a user-assigned managed identity — the raw key never appears in app configuration |
| Deploy | `azd env set NVD_API_KEY <key>` writes to `.azure/*/env.json` (gitignored by root `.gitignore`) |

## Helpful commands

```bash
# Redeploy code without reprovisioning infrastructure
azd deploy

# View live function logs
az webapp log tail --name <funcappname> --resource-group <rg>

# Tear down all Azure resources
azd down
```

## Source code

| File | Purpose |
|---|---|
| [src/function_app.py](src/function_app.py) | MCP tool definitions (`search_cves`, `get_cve`, `get_cve_history`) |
| [src/nvd_service.py](src/nvd_service.py) | NVD REST API client |
| [infra/main.bicep](infra/main.bicep) | Azure infrastructure (Functions, Key Vault, Storage, Monitoring) |
| [infra/app/keyvault.bicep](infra/app/keyvault.bicep) | Key Vault resource and RBAC role assignments |

## NVD API reference

- [CVE API](https://nvd.nist.gov/developers/vulnerabilities) — `GET /cves/2.0`
- [CVE History API](https://nvd.nist.gov/developers/vulnerabilities) — `GET /cvehistory/2.0`
- [Request an API key](https://nvd.nist.gov/developers/request-an-api-key)
