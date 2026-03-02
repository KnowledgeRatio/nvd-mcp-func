param name string
@description('Primary location for all resources.')
param location string = resourceGroup().location
param tags object = {}
param managedIdentityPrincipalId string
@description('Principal ID of the deploying user. Used to grant Secrets Officer access for managing secrets post-deployment.')
param userIdentityPrincipalId string = ''
param allowUserIdentityPrincipal bool = false

@secure()
@description('NVD API Key to store as a Key Vault secret. Leave empty to skip secret creation.')
param nvdApiKey string = ''

// Key Vault Secrets User — allows reading secret values (for the Function App managed identity)
var keyVaultSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'
// Key Vault Secrets Officer — allows creating and updating secrets (for the deploying user)
var keyVaultSecretsOfficerRoleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true   // Use RBAC rather than legacy access policies
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
  }
}

// Store the NVD API Key as a secret — only when a key was actually provided
resource nvdApiKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (!empty(nvdApiKey)) {
  parent: keyVault
  name: 'NVD-API-KEY'
  properties: {
    value: nvdApiKey
  }
}

// Grant the Function App's managed identity read access to secrets at runtime
resource kvSecretsUserManagedIdentity 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, managedIdentityPrincipalId, keyVaultSecretsUserRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
    principalId: managedIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Grant the deploying user Secrets Officer access so they can update the key post-deployment
resource kvSecretsOfficerUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (allowUserIdentityPrincipal && !empty(userIdentityPrincipalId)) {
  name: guid(keyVault.id, userIdentityPrincipalId, keyVaultSecretsOfficerRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsOfficerRoleId)
    principalId: userIdentityPrincipalId
    principalType: 'User'
  }
}

output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
