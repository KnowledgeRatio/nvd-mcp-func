You are an AI assistant helping the developer build, run, and deploy this NVD MCP Server project.

## Project overview

This is a Python Azure Functions v2 project that exposes the NIST National Vulnerability Database (NVD) REST APIs as MCP (Model Context Protocol) tools. It is deployed to Azure using `azd`.

## MCP tools available

- `search_cves` — search CVEs by keyword, severity, CWE, CPE, date, KEV filter
- `get_cve` — retrieve a specific CVE by ID
- `get_cve_history` — get change history for CVEs

## Key context

- The function app lives in `src/`. The entry point is `src/function_app.py`.
- NVD API client is in `src/nvd_service.py`. It reads `NVD_API_KEY` from the environment — the key is optional.
- For local dev, dependencies must be installed into a `.venv` inside `src/` so the Azure Functions Core Tools v2 Python worker can resolve them correctly.
- `local.settings.json` is gitignored. Users copy from `local.settings.json.example`.
- Secrets in Azure are stored in Key Vault and referenced from Function App settings via `@Microsoft.KeyVault(...)` — the managed identity handles access.
- AZD and `func` CLI are the main tools for deploy and local run.

## After `azd up` or `azd provision`

Once the user has deployed at least once, the `.azure/` folder contains environment variables. Use these to populate commands rather than asking for placeholder values:

```bash
FUNC=$(cat .azure/$(cat .azure/config.json | jq -r '.defaultEnvironment')/env.json | jq -r '.AZURE_FUNCTION_NAME')
RG=$(cat .azure/$(cat .azure/config.json | jq -r '.defaultEnvironment')/env.json | jq -r '.AZURE_RESOURCE_GROUP')
KV=$(cat .azure/$(cat .azure/config.json | jq -r '.defaultEnvironment')/env.json | jq -r '.AZURE_KEY_VAULT_NAME')
```

## If the user asks to test a tool

Use the MCP server endpoint directly if it is running. Do not ask the user to start it first — just note if it isn't reachable.
