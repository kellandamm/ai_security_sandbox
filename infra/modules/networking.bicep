@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Unique resource token')
param resourceToken string

@description('Additional FQDNs to allow through the firewall beyond defaults')
param allowedEgressFqdns array = []

var vnetName = 'vnet-${resourceToken}'
var firewallName = 'afw-${resourceToken}'
var firewallPipName = 'pip-afw-${resourceToken}'

// ─── Network Security Groups ──────────────────────────────────────────────────

resource nsgContainerApps 'Microsoft.Network/networkSecurityGroups@2023-06-01' = {
  name: 'nsg-container-apps-${resourceToken}'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowApimInbound'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '10.0.2.0/24'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        name: 'AllowAzureLoadBalancer'
        properties: {
          priority: 200
          protocol: '*'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: 'AzureLoadBalancer'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4096
          protocol: '*'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'AllowOutboundToFirewall'
        properties: {
          priority: 100
          protocol: '*'
          access: 'Allow'
          direction: 'Outbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.0.3.0/26'
          destinationPortRange: '*'
        }
      }
      {
        name: 'AllowOutboundToPrivateEndpoints'
        properties: {
          priority: 110
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Outbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.0.4.0/24'
          destinationPortRange: '443'
        }
      }
      {
        name: 'DenyAllOutbound'
        properties: {
          priority: 4096
          protocol: '*'
          access: 'Deny'
          direction: 'Outbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource nsgApim 'Microsoft.Network/networkSecurityGroups@2023-06-01' = {
  name: 'nsg-apim-${resourceToken}'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowApimManagement'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: 'ApiManagement'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '3443'
        }
      }
      {
        name: 'AllowHttpsInbound'
        properties: {
          priority: 110
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '443'
        }
      }
      {
        name: 'AllowAzureLoadBalancerApim'
        properties: {
          priority: 120
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: 'AzureLoadBalancer'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '6390'
        }
      }
    ]
  }
}

resource nsgPrivateEndpoints 'Microsoft.Network/networkSecurityGroups@2023-06-01' = {
  name: 'nsg-pe-${resourceToken}'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowVnetInbound'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4096
          protocol: '*'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// ─── Route Table (force-tunnel egress through Firewall) ───────────────────────

resource routeTable 'Microsoft.Network/routeTables@2023-06-01' = {
  name: 'rt-${resourceToken}'
  location: location
  tags: tags
  properties: {
    disableBgpRoutePropagation: true
    routes: [
      {
        name: 'DefaultToFirewall'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: '10.0.3.4' // Azure Firewall always gets .4 in its subnet
        }
      }
    ]
  }
}

// ─── Virtual Network ──────────────────────────────────────────────────────────

resource vnet 'Microsoft.Network/virtualNetworks@2023-06-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: ['10.0.0.0/16']
    }
    subnets: [
      {
        name: 'snet-container-apps'
        properties: {
          addressPrefix: '10.0.1.0/24'
          networkSecurityGroup: { id: nsgContainerApps.id }
          routeTable: { id: routeTable.id }
          delegations: [
            {
              name: 'AcaDelegation'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'snet-apim'
        properties: {
          addressPrefix: '10.0.2.0/24'
          networkSecurityGroup: { id: nsgApim.id }
        }
      }
      {
        name: 'AzureFirewallSubnet' // must be this exact name
        properties: {
          addressPrefix: '10.0.3.0/26'
        }
      }
      {
        name: 'snet-private-endpoints'
        properties: {
          addressPrefix: '10.0.4.0/24'
          networkSecurityGroup: { id: nsgPrivateEndpoints.id }
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

// ─── Azure Firewall ───────────────────────────────────────────────────────────

resource firewallPip 'Microsoft.Network/publicIPAddresses@2023-06-01' = {
  name: firewallPipName
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource firewallPolicy 'Microsoft.Network/firewallPolicies@2023-06-01' = {
  name: 'afwp-${resourceToken}'
  location: location
  tags: tags
  properties: {
    threatIntelMode: 'Alert'
    dnsSettings: {
      enableProxy: true // forces all container DNS queries through Firewall
      servers: []
    }
  }
}

resource firewallPolicyRuleGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2023-06-01' = {
  name: 'DefaultRules'
  parent: firewallPolicy
  properties: {
    priority: 200
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'AllowAzureServices'
        priority: 100
        action: { type: 'Allow' }
        rules: concat(
          [
            {
              ruleType: 'ApplicationRule'
              name: 'AllowAzureOpenAI'
              protocols: [{ protocolType: 'Https', port: 443 }]
              targetFqdns: ['*.openai.azure.com', '*.cognitiveservices.azure.com']
              sourceAddresses: ['10.0.1.0/24']
            }
            {
              ruleType: 'ApplicationRule'
              name: 'AllowAzureMonitor'
              protocols: [{ protocolType: 'Https', port: 443 }]
              targetFqdns: ['*.monitor.azure.com', '*.ods.opinsights.azure.com', '*.oms.opinsights.azure.com']
              sourceAddresses: ['10.0.1.0/24']
            }
            {
              ruleType: 'ApplicationRule'
              name: 'AllowKeyVault'
              protocols: [{ protocolType: 'Https', port: 443 }]
              targetFqdns: ['*.vault.azure.net']
              sourceAddresses: ['10.0.1.0/24']
            }
            {
              ruleType: 'ApplicationRule'
              name: 'AllowStorage'
              protocols: [{ protocolType: 'Https', port: 443 }]
              targetFqdns: ['*.blob.core.windows.net', '*.dfs.core.windows.net']
              sourceAddresses: ['10.0.1.0/24']
            }
            {
              ruleType: 'ApplicationRule'
              name: 'AllowAAD'
              protocols: [{ protocolType: 'Https', port: 443 }]
              targetFqdns: ['login.microsoftonline.com', '*.login.microsoft.com']
              sourceAddresses: ['10.0.1.0/24']
            }
            {
              ruleType: 'ApplicationRule'
              name: 'AllowACR'
              protocols: [{ protocolType: 'Https', port: 443 }]
              targetFqdns: ['*.azurecr.io', 'mcr.microsoft.com']
              sourceAddresses: ['10.0.1.0/24']
            }
            {
              ruleType: 'ApplicationRule'
              name: 'AllowAppConfig'
              protocols: [{ protocolType: 'Https', port: 443 }]
              targetFqdns: ['*.azconfig.io']
              sourceAddresses: ['10.0.1.0/24']
            }
          ],
          map(allowedEgressFqdns, fqdn => {
            ruleType: 'ApplicationRule'
            name: 'AllowCustom-${uniqueString(fqdn)}'
            protocols: [{ protocolType: 'Https', port: 443 }]
            targetFqdns: [fqdn]
            sourceAddresses: ['10.0.1.0/24']
          })
        )
      }
    ]
  }
}

resource firewall 'Microsoft.Network/azureFirewalls@2023-06-01' = {
  name: firewallName
  location: location
  tags: tags
  properties: {
    sku: { name: 'AZFW_VNet', tier: 'Standard' }
    firewallPolicy: { id: firewallPolicy.id }
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, 'AzureFirewallSubnet')
          }
          publicIPAddress: { id: firewallPip.id }
        }
      }
    ]
  }
  dependsOn: [vnet]
}

// ─── Private DNS Zones ────────────────────────────────────────────────────────

var privateDnsZones = [
  'privatelink.vaultcore.azure.net'
  'privatelink.blob.core.windows.net'
  'privatelink.dfs.core.windows.net'
  'privatelink.azurecr.io'
  'privatelink.monitor.azure.com'
  'privatelink.openai.azure.com'
  'privatelink.azconfig.io'
  'privatelink.azurewebsites.net'
]

resource dnsZones 'Microsoft.Network/privateDnsZones@2020-06-01' = [for zone in privateDnsZones: {
  name: zone
  location: 'global'
  tags: tags
}]

resource dnsZoneVnetLinks 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = [for (zone, i) in privateDnsZones: {
  name: '${zone}-link'
  parent: dnsZones[i]
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: { id: vnet.id }
  }
}]

// ─── Outputs ──────────────────────────────────────────────────────────────────

output vnetId string = vnet.id
output containerAppsSubnetId string = '${vnet.id}/subnets/snet-container-apps'
output apimSubnetId string = '${vnet.id}/subnets/snet-apim'
output firewallSubnetId string = '${vnet.id}/subnets/AzureFirewallSubnet'
output privateEndpointSubnetId string = '${vnet.id}/subnets/snet-private-endpoints'

// DNS zone IDs for private endpoints
output privateDnsZoneKeyVaultId string = dnsZones[0].id
output privateDnsZoneBlobId string = dnsZones[1].id
output privateDnsZoneDfsId string = dnsZones[2].id
output privateDnsZoneAcrId string = dnsZones[3].id
output privateDnsZoneMonitorId string = dnsZones[4].id
output privateDnsZoneOpenAiId string = dnsZones[5].id
output privateDnsZoneAppConfigId string = dnsZones[6].id
