param virtualNetworkName string
param subnetName string
@description('Specifies the Key Vault resource name')
param keyVaultName string
param location string = resourceGroup().location
param tags object = {}

resource vnet 'Microsoft.Network/virtualNetworks@2021-08-01' existing = {
  name: virtualNetworkName
}

resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' existing = {
  name: keyVaultName
}

var keyVaultPrivateDNSZoneName = 'privatelink.vaultcore.azure.net'

// AVM module for Key Vault Private Endpoint
module keyVaultPrivateEndpoint 'br/public:avm/res/network/private-endpoint:0.11.0' = {
  name: 'keyvault-private-endpoint-deployment'
  params: {
    name: 'keyvault-private-endpoint'
    location: location
    tags: tags
    subnetResourceId: '${vnet.id}/subnets/${subnetName}'
    privateLinkServiceConnections: [
      {
        name: 'keyVaultPrivateLinkConnection'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
    customDnsConfigs: []
    privateDnsZoneGroup: {
      name: 'keyVaultPrivateDnsZoneGroup'
      privateDnsZoneGroupConfigs: [
        {
          name: 'keyVaultARecord'
          privateDnsZoneResourceId: privateDnsZoneKeyVaultDeployment.outputs.resourceId
        }
      ]
    }
  }
}

// AVM module for Key Vault Private DNS Zone
module privateDnsZoneKeyVaultDeployment 'br/public:avm/res/network/private-dns-zone:0.7.1' = {
  name: 'keyvault-private-dns-zone-deployment'
  params: {
    name: keyVaultPrivateDNSZoneName
    location: 'global'
    tags: tags
    virtualNetworkLinks: [
      {
        name: '${keyVaultName}-link-${take(toLower(uniqueString(keyVaultName, virtualNetworkName)), 4)}'
        virtualNetworkResourceId: vnet.id
        registrationEnabled: false
        location: 'global'
        tags: tags
      }
    ]
  }
}
