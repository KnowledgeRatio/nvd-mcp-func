#!/usr/bin/env bash
# Pre-provision hook: creates an Entra app registration for MCP server EasyAuth.
#
# Auth modes controlled by azd env vars:
#   ENTRA_AUTH_ENABLED=true  -> Creates app registration, enables EasyAuth in Bicep.
#                               Supports: Entra (Project MI), OAuth identity passthrough.
#   MCP_UNAUTHENTICATED_ACCESS=true -> Disables MCP key auth with no EasyAuth.
#                               WARNING: endpoint becomes publicly accessible.
#   (neither set)            -> Key-based auth (default). No changes made.

set -euo pipefail

if [ "${MCP_UNAUTHENTICATED_ACCESS:-}" = "true" ]; then
    echo ""
    echo "============================================================"
    echo "  WARNING: MCP_UNAUTHENTICATED_ACCESS=true"
    echo "  The MCP server endpoint will be publicly accessible"
    echo "  without any authentication."
    echo "  Use only for tools that expose read-only public data"
    echo "  or in fully isolated development environments."
    echo "  Set ENTRA_AUTH_ENABLED=true for production deployments."
    echo "============================================================"
    echo ""
    exit 0
fi

if [ "${ENTRA_AUTH_ENABLED:-}" != "true" ]; then
    echo "ENTRA_AUTH_ENABLED not set — using key-based auth (default)."
    echo "To enable Entra authentication: azd env set ENTRA_AUTH_ENABLED true"
    exit 0
fi

echo "ENTRA_AUTH_ENABLED=true — setting up Entra app registration..."

# Ensure az CLI is authenticated — reuse existing session or prompt for login
if ! az account show > /dev/null 2>&1; then
    echo "Azure CLI not authenticated. Logging in..."
    az login --use-device-code
fi

DISPLAY_NAME="nvd-mcp-${AZURE_ENV_NAME}"

# Idempotent: reuse existing registration if it already exists
EXISTING=$(az ad app list --display-name "$DISPLAY_NAME" --query "[0].appId" -o tsv 2>/dev/null || true)

if [ -n "$EXISTING" ]; then
    APP_ID="$EXISTING"
    ID_URI="api://$APP_ID"
    echo "Reusing existing Entra app registration: $APP_ID"
else
    echo "Creating new Entra app registration: $DISPLAY_NAME"
    APP_ID=$(az ad app create \
        --display-name "$DISPLAY_NAME" \
        --query appId -o tsv)
    echo "Created app registration: $APP_ID"

    # Set identifier URI to api://{appId} — always valid per tenant policy
    ID_URI="api://$APP_ID"
    az ad app update --id "$APP_ID" --identifier-uris "$ID_URI" > /dev/null 2>&1 || \
        echo "WARNING: Could not set identifier URI — set manually if needed."

    # Expose user_impersonation scope (OAuth identity passthrough)
    # and MCP.Access app role (Entra Agent ID / application permissions)
    SCOPE_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
    ROLE_ID=$(python3 -c "import uuid; print(uuid.uuid4())")

    SCOPE_JSON="{\"oauth2PermissionScopes\":[{\"id\":\"$SCOPE_ID\",\"value\":\"user_impersonation\",\"type\":\"User\",\"adminConsentDisplayName\":\"Access NVD MCP Server\",\"adminConsentDescription\":\"Allows the application to access the NVD MCP Server on behalf of the signed-in user.\",\"userConsentDisplayName\":\"Access NVD MCP Server\",\"userConsentDescription\":\"Allow this application to access the NVD MCP Server on your behalf.\",\"isEnabled\":true}]}"

    if az ad app update --id "$APP_ID" --set "api=$SCOPE_JSON" > /dev/null 2>&1; then
        echo "Exposed user_impersonation scope on app registration."
    else
        echo "WARNING: Could not set user_impersonation scope — OAuth passthrough may not work."
    fi

    # Add MCP.Access app role for Entra Agent ID (application permissions)
    ROLE_JSON="[{\"id\":\"$ROLE_ID\",\"value\":\"MCP.Access\",\"displayName\":\"Access NVD MCP Server\",\"description\":\"Allows an application (e.g. an Azure AI Foundry agent) to call the NVD MCP Server using its own identity.\",\"allowedMemberTypes\":[\"Application\"],\"isEnabled\":true}]"
    if az ad app update --id "$APP_ID" --app-roles "$ROLE_JSON" > /dev/null 2>&1; then
        echo "Added MCP.Access app role for Agent ID authentication."
    else
        echo "WARNING: Could not add MCP.Access app role — Agent ID auth may not work."
    fi
fi

azd env set ENTRA_APP_CLIENT_ID "$APP_ID"

echo ""
echo "Entra app registration ready."
echo "  App ID:             $APP_ID"
echo "  Application ID URI: $ID_URI"
echo ""
echo "After deployment, use these values to connect Foundry agents:"
echo "  Entra (Project MI) Audience: $ID_URI"
echo "  OAuth Passthrough Scopes:    $ID_URI/user_impersonation"
echo ""
echo "Note: Entra - Agent Identity is not yet supported for Functions-based MCP servers."
echo "      Use Project Managed Identity for production Entra scenarios."
