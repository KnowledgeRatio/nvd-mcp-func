# Pre-provision hook: creates an Entra app registration for MCP server EasyAuth.
#
# Auth modes controlled by azd env vars:
#   ENTRA_AUTH_ENABLED=true  -> Creates app registration, enables EasyAuth in Bicep.
#                               Supports: Entra (Project MI), OAuth identity passthrough.
#   MCP_UNAUTHENTICATED_ACCESS=true -> Disables MCP key auth with no EasyAuth.
#                               WARNING: endpoint becomes publicly accessible.
#   (neither set)            -> Key-based auth (default). No changes made.

if ($env:MCP_UNAUTHENTICATED_ACCESS -eq 'true') {
    Write-Warning ""
    Write-Warning "============================================================"
    Write-Warning "  WARNING: MCP_UNAUTHENTICATED_ACCESS=true"
    Write-Warning "  The MCP server endpoint will be publicly accessible"
    Write-Warning "  without any authentication."
    Write-Warning "  Use only for tools that expose read-only public data"
    Write-Warning "  or in fully isolated development environments."
    Write-Warning "  Set ENTRA_AUTH_ENABLED=true for production deployments."
    Write-Warning "============================================================"
    Write-Warning ""
    exit 0
}

if ($env:ENTRA_AUTH_ENABLED -ne 'true') {
    Write-Host "ENTRA_AUTH_ENABLED not set — using key-based auth (default)."
    Write-Host "To enable Entra authentication: azd env set ENTRA_AUTH_ENABLED true"
    exit 0
}

Write-Host "ENTRA_AUTH_ENABLED=true — setting up Entra app registration..."

# Ensure az CLI is authenticated — reuse existing session or prompt for login
$accountCheck = az account show 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Azure CLI not authenticated. Logging in..."
    az login --use-device-code
}

$displayName = "nvd-mcp-$env:AZURE_ENV_NAME"
$idUri = "api://nvd-mcp-$env:AZURE_ENV_NAME"

# Idempotent: reuse existing registration if it already exists
$existing = az ad app list --display-name $displayName --query "[0].appId" -o tsv 2>$null
if ($LASTEXITCODE -ne 0) { $existing = $null }

if (![string]::IsNullOrWhiteSpace($existing)) {
    $appId = $existing.Trim()
    $idUri = "api://$appId"
    Write-Host "Reusing existing Entra app registration: $appId"
} else {
    Write-Host "Creating new Entra app registration: $displayName"
    $appId = az ad app create `
        --display-name $displayName `
        --query appId -o tsv
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create Entra app registration."
        exit 1
    }
    $appId = $appId.Trim()
    Write-Host "Created app registration: $appId"

    # Set identifier URI to api://{appId} — always valid per tenant policy
    $idUri = "api://$appId"
    az ad app update --id $appId --identifier-uris $idUri | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not set identifier URI — set manually if needed."
    }

    # Expose user_impersonation scope (OAuth identity passthrough)
    # and MCP.Access app role (Entra Agent ID / application permissions)
    $scopeId = [guid]::NewGuid().ToString()
    $roleId  = [guid]::NewGuid().ToString()

    $scopeJson = @"
{"oauth2PermissionScopes":[{"id":"$scopeId","value":"user_impersonation","type":"User","adminConsentDisplayName":"Access NVD MCP Server","adminConsentDescription":"Allows the application to access the NVD MCP Server on behalf of the signed-in user.","userConsentDisplayName":"Access NVD MCP Server","userConsentDescription":"Allow this application to access the NVD MCP Server on your behalf.","isEnabled":true}]}
"@
    az ad app update --id $appId --set "api=$scopeJson" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not set user_impersonation scope — OAuth passthrough may not work."
    } else {
        Write-Host "Exposed user_impersonation scope on app registration."
    }

    # Add MCP.Access app role for Entra Agent ID (application permissions)
    $roleJson = @"
[{"id":"$roleId","value":"MCP.Access","displayName":"Access NVD MCP Server","description":"Allows an application (e.g. an Azure AI Foundry agent) to call the NVD MCP Server using its own identity.","allowedMemberTypes":["Application"],"isEnabled":true}]
"@
    az ad app update --id $appId --app-roles $roleJson | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not add MCP.Access app role — Agent ID auth may not work."
    } else {
        Write-Host "Added MCP.Access app role for Agent ID authentication."
    }
}

azd env set ENTRA_APP_CLIENT_ID $appId

Write-Host ""
Write-Host "Entra app registration ready."
Write-Host "  App ID:             $appId"
Write-Host "  Application ID URI: $idUri"
Write-Host ""
Write-Host "After deployment, use these values to connect Foundry agents:"
Write-Host "  Entra (Project MI) Audience: $idUri"
Write-Host "  OAuth Passthrough Scopes:    $idUri/user_impersonation"
Write-Host ""
Write-Host "Note: Entra - Agent Identity is not yet supported for Functions-based MCP servers."
Write-Host "      Use Project Managed Identity for production Entra scenarios."
