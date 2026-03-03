param virtualNetworkName string
param subnetName string
@description('Specifies the Function App resource name')
param functionAppName string
param location string = resourceGroup().location
param tags object = {}

resource vnet 'Microsoft.Network/virtualNetworks@2021-08-01' existing = {
  name: virtualNetworkName
}

resource functionApp 'Microsoft.Web/sites@2022-03-01' existing = {
  name: functionAppName
}

var functionAppPrivateDNSZoneName = 'privatelink.azurewebsites.net'

// AVM module for Function App Private Endpoint
module functionAppPrivateEndpoint 'br/public:avm/res/network/private-endpoint:0.11.0' = {
  name: 'functionapp-private-endpoint-deployment'
  params: {
    name: 'functionapp-private-endpoint'
    location: location
    tags: tags
    subnetResourceId: '${vnet.id}/subnets/${subnetName}'
    privateLinkServiceConnections: [
      {
        name: 'functionAppPrivateLinkConnection'
        properties: {
          privateLinkServiceId: functionApp.id
          groupIds: [
            'sites'
          ]
        }
      }
    ]
    customDnsConfigs: []
    privateDnsZoneGroup: {
      name: 'functionAppPrivateDnsZoneGroup'
      privateDnsZoneGroupConfigs: [
        {
          name: 'functionAppARecord'
          privateDnsZoneResourceId: privateDnsZoneFunctionAppDeployment.outputs.resourceId
        }
      ]
    }
  }
}

// AVM module for Function App Private DNS Zone
module privateDnsZoneFunctionAppDeployment 'br/public:avm/res/network/private-dns-zone:0.7.1' = {
  name: 'functionapp-private-dns-zone-deployment'
  params: {
    name: functionAppPrivateDNSZoneName
    location: 'global'
    tags: tags
    virtualNetworkLinks: [
      {
        name: '${functionAppName}-link-${take(toLower(uniqueString(functionAppName, virtualNetworkName)), 4)}'
        virtualNetworkResourceId: vnet.id
        registrationEnabled: false
        location: 'global'
        tags: tags
      }
    ]
  }
}
