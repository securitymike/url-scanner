// URL Safety Scanner infrastructure:
// Static Web App (Standard, required for linked backends) -> linked Function App (Durable Functions)
// Function App system-assigned identity -> Key Vault (RBAC, "Key Vault Secrets User").

@description('Short prefix used in resource names (letters, digits, hyphens).')
@maxLength(12)
param namePrefix string = 'urlscan'

@description('Region for the Function App, Key Vault, Storage and monitoring.')
param location string = resourceGroup().location

@description('Region for the Static Web App (limited set of regions).')
@allowed(['westus2', 'centralus', 'eastus2', 'westeurope', 'eastasia'])
param staticWebAppLocation string = 'eastus2'

@description('Treat sites with file sharing capability as UNSAFE.')
param policyBlockFileSharing bool = true

@description('Treat sites that use AI as UNSAFE.')
param policyBlockAi bool = true

@description('Minimum number of reputation sources that must respond; fewer = UNSAFE (fail closed).')
@minValue(0)
@maxValue(4)
param minReputationSources int = 2

@description('urlscan.io scan visibility: public, unlisted or private (private needs a paid plan).')
@allowed(['public', 'unlisted', 'private'])
param urlscanVisibility string = 'unlisted'

@description('Claude model used by the content classifier.')
param anthropicModel string = 'claude-opus-5'

@description('Entra ID app registration client ID used for sign-in to the Static Web App.')
param entraClientId string

@description('Entra ID app registration client secret used for sign-in to the Static Web App.')
@secure()
param entraClientSecret string

@description('Optional object ID of the deploying user/group, granted "Key Vault Secrets Officer" so it can load API keys.')
param secretsAdminPrincipalId string = ''

var suffix = uniqueString(resourceGroup().id)
var cleanPrefix = toLower(replace(namePrefix, '-', ''))
var storageName = take('st${cleanPrefix}${suffix}', 24)
var functionAppName = '${namePrefix}-func-${suffix}'
var keyVaultName = take('kv-${cleanPrefix}-${suffix}', 24)
var keyVaultSecretsUserRole = '4633458b-17de-408a-b874-0445c86b69e6'
var keyVaultSecretsOfficerRole = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

var storageConnection = 'DefaultEndpointsProtocol=https;AccountName=${storage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storage.listKeys().keys[0].value}'

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-logs-${suffix}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${namePrefix}-ai-${suffix}'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logs.id
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: 'Enabled'
  }
}

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${namePrefix}-plan-${suffix}'
  location: location
  sku: { name: 'Y1', tier: 'Dynamic' }
  properties: {}
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      appSettings: [
        { name: 'AzureWebJobsStorage', value: storageConnection }
        { name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING', value: storageConnection }
        { name: 'WEBSITE_CONTENTSHARE', value: toLower(functionAppName) }
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'node' }
        { name: 'WEBSITE_NODE_DEFAULT_VERSION', value: '~22' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsights.properties.ConnectionString }
        { name: 'KEY_VAULT_URL', value: keyVault.properties.vaultUri }
        { name: 'POLICY_BLOCK_FILE_SHARING', value: string(policyBlockFileSharing) }
        { name: 'POLICY_BLOCK_AI', value: string(policyBlockAi) }
        { name: 'MIN_REPUTATION_SOURCES', value: string(minReputationSources) }
        { name: 'VT_MALICIOUS_THRESHOLD', value: '2' }
        { name: 'NEW_DOMAIN_DAYS', value: '30' }
        { name: 'URLSCAN_VISIBILITY', value: urlscanVisibility }
        { name: 'DIRECT_FETCH_ENABLED', value: 'true' }
        { name: 'ANTHROPIC_MODEL', value: anthropicModel }
        { name: 'ANTHROPIC_EFFORT', value: 'medium' }
      ]
    }
  }
}

resource functionSecretsAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: keyVault
  name: guid(keyVault.id, functionApp.id, keyVaultSecretsUserRole)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRole)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource adminSecretsAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(secretsAdminPrincipalId)) {
  scope: keyVault
  name: guid(keyVault.id, secretsAdminPrincipalId, keyVaultSecretsOfficerRole)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsOfficerRole)
    principalId: secretsAdminPrincipalId
  }
}

resource staticWebApp 'Microsoft.Web/staticSites@2023-12-01' = {
  name: '${namePrefix}-web-${suffix}'
  location: staticWebAppLocation
  sku: { name: 'Standard', tier: 'Standard' }
  properties: {
    stagingEnvironmentPolicy: 'Disabled'
    allowConfigFileUpdates: true
  }
}

resource staticWebAppSettings 'Microsoft.Web/staticSites/config@2023-12-01' = {
  parent: staticWebApp
  name: 'appsettings'
  properties: {
    AZURE_CLIENT_ID: entraClientId
    AZURE_CLIENT_SECRET: entraClientSecret
  }
}

// Linking routes /api/* on the Static Web App to the Function App and locks the
// Function App down so it only accepts traffic from the Static Web App.
resource linkedBackend 'Microsoft.Web/staticSites/linkedBackends@2023-12-01' = {
  parent: staticWebApp
  name: 'backend'
  properties: {
    backendResourceId: functionApp.id
    region: location
  }
}

output functionAppName string = functionApp.name
output staticWebAppName string = staticWebApp.name
output staticWebAppUrl string = 'https://${staticWebApp.properties.defaultHostname}'
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
