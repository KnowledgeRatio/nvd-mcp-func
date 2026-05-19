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

---

## Available MCP Tools

| Tool | Description |
|---|---|
| [`search_cves`](#search_cves) | Search the CVE database by keyword, severity, CWE, CPE, date ranges, KEV membership, and more |
| [`get_cve`](#get_cve) | Retrieve full details for a specific CVE (CVSS scores, affected configurations, references) |
| [`get_cve_history`](#get_cve_history) | Get the NVD change history for CVE records — shows when scores, status, or analysis were updated |
| [`search_cves_by_cpe`](#search_cves_by_cpe) | Find all CVEs affecting a specific product by its CPE 2.3 name |
| [`get_recent_cves`](#get_recent_cves) | Get CVEs published in the last N days, optionally filtered by severity or KEV status |
| [`search_cpes`](#search_cpes) | Search for CPE product entries by name — use this to find the exact CPE URI for other tools |
| [`get_kev`](#get_kev) | Fetch the CISA Known Exploited Vulnerabilities catalog live, with keyword/date/ransomware filtering |

---

## Quickstart — GitHub Codespaces (zero local install)

The repo includes a pre-configured dev container that has all tools installed automatically (Python, azd, az, func, Node, Azurite, MCP Inspector).

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/KnowledgeRatio/nvd-mcp-func)

Or open locally in VS Code:

1. Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
2. Clone the repo and open it in VS Code
3. When prompted, click **Reopen in Container**

Everything in the [Run locally](#run-locally) and [Deploy to Azure](#deploy-to-azure) sections will work inside the container without installing anything on your machine.

> **Note (Codespaces):** Azurite starts automatically in the background every time the container starts. You can proceed directly to step 2 of [Run locally](#run-locally).

---

## Prerequisites

- [Python](https://www.python.org/downloads/) 3.12 recommended (matches deployed Functions runtime), 3.11+ supported for local development
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
winget install OpenJS.NodeJS.LTS
npm install -g azure-functions-core-tools@4 --unsafe-perm true
```

---

## Run locally

### 1. Start the storage emulator

Azurite emulates Azure Storage locally and is required by the Functions host.

```shell
npx azurite --location ~/.azurite --silent
```

Leave this running in a separate terminal tab.

> **Codespaces:** Azurite is already running — skip this step.

### 2. Create a virtual environment and install dependencies

The Python worker resolves packages from a `.venv` folder inside `src/`.

```shell
cd src
python -m venv .venv
```

Install dependencies:

```shell
# macOS / Linux
.venv/bin/pip install -r requirements.txt

# Windows (PowerShell)
.venv\Scripts\pip install -r requirements.txt
```

**Verify the install succeeded:**

```shell
# macOS / Linux
.venv/bin/python -c "import azure.functions; print('OK')"

# Windows
.venv\Scripts\python -c "import azure.functions; print('OK')"
```

Expected output: `OK`

### 3. Configure local settings

```shell
# macOS / Linux
cp src/local.settings.json.example src/local.settings.json

# Windows PowerShell
Copy-Item src\local.settings.json.example src\local.settings.json
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

Wait until you see output similar to:

```
Azure Functions Core Tools
...
Functions:
        search_cves: [POST,GET] http://localhost:7071/runtime/webhooks/mcp
        get_cve: [POST,GET] http://localhost:7071/runtime/webhooks/mcp
        ...
Host lock lease acquired by instance ID ...
```

The MCP server is now available at `http://localhost:7071/runtime/webhooks/mcp`.

> **Troubleshooting:** If `func start` fails with a storage error, make sure Azurite is running (step 1). If it fails with an import error, ensure you installed dependencies into `src/.venv` (step 2).

---

## Connect from a client

### VS Code — GitHub Copilot agent mode

Open `.vscode/mcp.json`. Click **Start** above the `local-mcp-function` server entry. Then ask Copilot:

```
Search for critical CVEs related to log4j
```

```
Get the full details for CVE-2021-44228
```

```
What CVEs have been added to the KEV catalog in the last 30 days?
```

### MCP Inspector

```shell
npx @modelcontextprotocol/inspector
```

Set transport to `Streamable HTTP`, URL to `http://localhost:7071/runtime/webhooks/mcp`, and click **Connect**.

---

## Deploy to Azure

### 1. Log in to Azure

```shell
azd auth login
```

Also log in with the Azure CLI (required for some post-deployment steps):

```shell
az login
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

Choose exactly one authentication mode before `azd up`:

| Mode | Env vars to set | Behavior |
|---|---|---|
| Key-based (default) | None | MCP webhook uses Functions system key auth |
| Entra (EasyAuth) | `azd env set ENTRA_AUTH_ENABLED true` | Preprovision hook creates/reuses app registration and sets `ENTRA_APP_CLIENT_ID`; webhook auth is delegated to EasyAuth |
| Unauthenticated (dev only) | `azd env set MCP_UNAUTHENTICATED_ACCESS true` | MCP webhook is publicly accessible with no auth |

> Do not set both `ENTRA_AUTH_ENABLED=true` and `MCP_UNAUTHENTICATED_ACCESS=true`. If both are set, the preprovision hook prioritizes unauthenticated access.

Quick verification:

```shell
azd env get-values
```

> **Multiple subscriptions?** If your account has more than one subscription, also run:
> ```shell
> azd env set AZURE_SUBSCRIPTION_ID <your-subscription-id>
> ```

### 4. (Optional) Set your NVD API key

```shell
azd env set NVD_API_KEY <your-key>
```

If you skip this step, the server deploys and works unauthenticated against NVD (lower NVD rate limits). You can add the key later.

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

> If `VNET_ENABLED=true`, Function App public network access is disabled and the MCP endpoint is only reachable from the private network.

When deployment completes, `azd up` prints the MCP endpoint URL:

```
Outputs:
  MCP_ENDPOINT: https://<funcappname>.azurewebsites.net/runtime/webhooks/mcp
```

### 6. Connect to the remote MCP server

Your endpoint format:

`https://<funcappname>.azurewebsites.net/runtime/webhooks/mcp`

#### Key-based mode (default)

Get the system key:

```shell
az functionapp keys list \
  --name <function-app-name> \
  --resource-group <resource-group> \
  --query "systemKeys.mcp_extension" -o tsv
```

In VS Code, click **Start** on `remote-mcp-function` in `.vscode/mcp.json` and provide function app name + system key.

#### Entra mode (`ENTRA_AUTH_ENABLED=true`)

Use a bearer token for scope `api://<ENTRA_APP_CLIENT_ID>/user_impersonation` instead of `x-functions-key`.

```shell
az account get-access-token \
  --scope "api://<ENTRA_APP_CLIENT_ID>/user_impersonation" \
  --query accessToken -o tsv
```

Configure your MCP client to send:

`Authorization: Bearer <access-token>`

#### Unauthenticated mode (`MCP_UNAUTHENTICATED_ACCESS=true`)

No auth header is required. Use only for isolated development scenarios.

### Update the NVD API key after deployment

```shell
az keyvault secret set \
  --vault-name <keyvault-name> \
  --name NVD-API-KEY \
  --value <new-key>
```

The Function App resolves the Key Vault reference automatically on next invocation (cached up to ~24h; restart the app for immediate effect).

> This command requires RBAC permission to write Key Vault secrets (for example, `Key Vault Secrets Officer`). The current template defaults to least privilege and does not auto-assign this role to the deploying user.

---

## Secrets management

| Context | How the key is stored |
|---|---|
| Local | `src/local.settings.json` (gitignored) |
| Azure | Azure Key Vault secret; Function App reads it at runtime via a Key Vault reference using a user-assigned managed identity — the raw key never appears in app configuration |
| Deploy | `azd env set NVD_API_KEY <key>` writes to `.azure/*/env.json` (gitignored by root `.gitignore`, but still plaintext on your machine) |

---

## Helpful commands

```bash
# Redeploy code without reprovisioning infrastructure
azd deploy

# View live function logs
az webapp log tail --name <funcappname> --resource-group <rg>

# Tear down all Azure resources
azd down
```

---

## MCP Tools Reference

Each tool below documents its parameters and gives example prompts. When used via an AI assistant (e.g. GitHub Copilot), the AI selects the appropriate tool and fills in the parameters based on the conversation.

---

### `search_cves`

Search the NVD CVE database with flexible filters. Returns matching vulnerabilities with CVSS scores, descriptions, references, and metadata.

**Parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `keyword` | string | No | Keywords to search within CVE descriptions and titles (e.g. `log4j`, `remote code execution`) |
| `cve_id` | string | No | A specific CVE identifier (e.g. `CVE-2021-44228`). When provided, other filters are ignored |
| `cpe_name` | string | No | CPE 2.3 name to filter CVEs for a specific product (e.g. `cpe:2.3:a:apache:log4j:*`) |
| `cvss_v3_severity` | string | No | Filter by CVSS v3 severity: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `cwe_id` | string | No | Filter by CWE identifier (e.g. `CWE-79` for XSS) |
| `pub_start_date` | string | No | Publication start date in ISO 8601 format (e.g. `2024-01-01T00:00:00.000`). Max range: 120 days |
| `pub_end_date` | string | No | Publication end date in ISO 8601 format. Max range: 120 days |
| `last_mod_start_date` | string | No | Last-modified start date in ISO 8601 format. Max range: 120 days |
| `last_mod_end_date` | string | No | Last-modified end date in ISO 8601 format. Max range: 120 days |
| `has_kev` | boolean | No | When `true`, return only CVEs in the CISA Known Exploited Vulnerabilities catalog |
| `results_per_page` | integer | No | Results per page (1–2000). Default: `20` |
| `start_index` | integer | No | Zero-based index for pagination. Default: `0` |

**Example prompts**

```
Search for critical CVEs related to log4j
Find all XSS vulnerabilities (CWE-79) published this year
Show me HIGH severity CVEs that are in the KEV catalog
Search for CVEs affecting Apache HTTP Server published between 2024-01-01 and 2024-03-31
```

---

### `get_cve`

Retrieve the complete record for a single CVE by its identifier. Returns CVSS v2 and v3 scores, weakness data (CWE), affected product configurations (CPE), reference links, and current status.

**Parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `cve_id` | string | **Yes** | The CVE identifier (e.g. `CVE-2021-44228`) |

**Example prompts**

```
Get the full details for CVE-2021-44228
What is the CVSS score and description for CVE-2023-44487?
Show me all affected products for CVE-2024-3094
```

---

### `get_cve_history`

Retrieve the NVD change history for CVE records. Useful for auditing when a vulnerability was initially analysed, when scores were revised, or when the status changed to Rejected.

**Parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `cve_id` | string | No | Retrieve history for a specific CVE. Leave empty to query by date range |
| `change_start_date` | string | No | Start of the change-event date range in ISO 8601 format. Max range: 120 days |
| `change_end_date` | string | No | End of the change-event date range in ISO 8601 format. Max range: 120 days |
| `event_name` | string | No | Filter by event type: `Initial Analysis`, `Reanalysis`, `CVE Modified`, `CVE Rejected`, `CVE Translated` |
| `results_per_page` | integer | No | Results per page (1–5000). Default: `20` |
| `start_index` | integer | No | Zero-based index for pagination. Default: `0` |

> **Note:** You must supply either `cve_id` or a date range (`change_start_date` + `change_end_date`). Supplying neither returns an API error.

**Example prompts**

```
Show the change history for CVE-2021-44228
What CVE records were modified in the NVD last week?
List all CVEs that were rejected between 2024-01-01 and 2024-03-31
When was CVE-2023-44487 first analysed?
```

---

### `search_cves_by_cpe`

Find all CVEs that affect a specific product using its CPE 2.3 name. Use [`search_cpes`](#search_cpes) first to discover the exact CPE URI.

**Parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `cpe_name` | string | **Yes** | CPE 2.3 name (e.g. `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*`) |
| `results_per_page` | integer | No | Results per page (1–2000). Default: `20` |
| `start_index` | integer | No | Zero-based index for pagination. Default: `0` |

**Example prompts**

```
Find all CVEs for Apache Log4j 2.14.1
What vulnerabilities affect OpenSSL 3.0?
```

---

### `get_recent_cves`

Get CVEs published in the last N days. A quick way to see what new vulnerabilities have been disclosed, optionally filtered by severity or KEV status.

**Parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `days` | integer | No | How many days back to look (1–120). Default: `7` |
| `cvss_v3_severity` | string | No | Filter by CVSS v3 severity: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `has_kev` | boolean | No | When `true`, return only CVEs in the CISA KEV catalog |
| `results_per_page` | integer | No | Results per page (1–2000). Default: `20` |
| `start_index` | integer | No | Zero-based index for pagination. Default: `0` |

**Example prompts**

```
What critical CVEs were published in the last 7 days?
Show me new HIGH or CRITICAL vulnerabilities from the past 30 days
What recently published CVEs are already in the KEV catalog?
Give me a summary of this week's new vulnerabilities
```

---

### `search_cpes`

Search the NVD CPE (Common Platform Enumeration) dictionary for product entries. Use this to find the exact CPE 2.3 URI needed by [`search_cves_by_cpe`](#search_cves_by_cpe) or the `cpe_name` filter in [`search_cves`](#search_cves).

**Parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `keyword` | string | No | Product name or vendor keyword (e.g. `apache tomcat`, `openssl`) |
| `cpe_match_string` | string | No | Partial CPE 2.3 string to match against (e.g. `cpe:2.3:a:microsoft`) |
| `results_per_page` | integer | No | Results per page (1–10000). Default: `20` |
| `start_index` | integer | No | Zero-based index for pagination. Default: `0` |

**Example prompts**

```
Find the CPE name for Apache Tomcat 10
What is the exact CPE identifier for OpenSSL 3.1.0?
Search for all Microsoft products in the CPE dictionary
```

---

### `get_kev`

Fetch the CISA Known Exploited Vulnerabilities (KEV) catalog live. The KEV catalog lists vulnerabilities that are known to be actively exploited in the wild and are subject to CISA binding operational directive BOD 22-01.

**Parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `keyword` | string | No | Filter by vendor, product, or vulnerability name (case-insensitive) |
| `since` | string | No | Only return entries added to KEV on or after this date (`YYYY-MM-DD`) |
| `ransomware_only` | boolean | No | When `true`, return only entries with a known ransomware campaign association |
| `results_per_page` | integer | No | Maximum entries to return (1–2000). Default: `10` |

**Example prompts**

```
What are the most recently added entries to the CISA KEV catalog?
Show me KEV entries added since 2024-01-01
Which KEV vulnerabilities are associated with ransomware campaigns?
Are there any Citrix products in the KEV catalog?
```

---

## Source code

| File | Purpose |
|---|---|
| [src/function_app.py](src/function_app.py) | MCP tool definitions (`search_cves`, `get_cve`, `get_cve_history`, `search_cves_by_cpe`, `get_recent_cves`, `search_cpes`, `get_kev`) |
| [src/nvd_service.py](src/nvd_service.py) | NVD REST API client and CISA KEV catalog fetcher |
| [infra/main.bicep](infra/main.bicep) | Azure infrastructure (Functions, Key Vault, Storage, Monitoring) |
| [infra/app/keyvault.bicep](infra/app/keyvault.bicep) | Key Vault resource and RBAC role assignments |

---

## NVD API reference

- [CVE API](https://nvd.nist.gov/developers/vulnerabilities) — `GET /cves/2.0`
- [CVE History API](https://nvd.nist.gov/developers/vulnerabilities) — `GET /cvehistory/2.0`
- [CPE API](https://nvd.nist.gov/developers/products) — `GET /cpes/2.0`
- [Request an API key](https://nvd.nist.gov/developers/request-an-api-key)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — live JSON feed

---

## Troubleshooting

**`func start` fails with "Microsoft.Azure.Storage.Common" or storage-related errors**

Azurite is not running. Start it in a separate terminal:

```shell
npx azurite --location ~/.azurite --silent
```

**`func start` fails with "ModuleNotFoundError: No module named 'azure.functions'"**

Dependencies were not installed into `src/.venv`. Run:

```shell
cd src
python -m venv .venv
.venv/bin/pip install -r requirements.txt   # macOS/Linux
# or
.venv\Scripts\pip install -r requirements.txt   # Windows
```

**NVD API returns 403 or rate-limit errors**

Without an API key the NVD API allows 5 requests per 30-second window. Add your key to `src/local.settings.json` (local) or run `azd env set NVD_API_KEY <key>` before deploying.

**`azd up` fails with "VNET_ENABLED is not set"**

This variable is required. Set it before deploying:

```shell
azd env set VNET_ENABLED false   # public access
# or
azd env set VNET_ENABLED true    # private/VNet-only access
```

**Can't update the NVD API key in Key Vault after deployment**

By default, the template does not grant the deploying user the `Key Vault Secrets Officer` role (least privilege). To enable key updates, assign the role manually:

```shell
KV=$(az keyvault list --resource-group <rg> --query "[0].name" -o tsv)
az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee <your-user-object-id> \
  --scope $(az keyvault show --name $KV --query id -o tsv)
```

Then set the secret:

```shell
az keyvault secret set --vault-name $KV --name NVD-API-KEY --value <new-key>
```

**MCP client shows "connection refused" for local server**

Ensure `func start` is running and listening on port 7071. Check the terminal where you ran `func start` for errors.

**Devcontainer / Codespace: Azurite not running after container restart**

Azurite is configured to start automatically via `postStartCommand`. If it is not running, start it manually:

```shell
nohup npx azurite --location ~/.azurite --silent > ~/.azurite/azurite.log 2>&1 &
```
