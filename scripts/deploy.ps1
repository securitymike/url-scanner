<#
.SYNOPSIS
  Provisions Azure resources and deploys the URL Safety Scanner (API + frontend).

.PREREQUISITES
  Azure CLI (az login done), Node.js 20+, Azure Functions Core Tools v4 (func),
  Static Web Apps CLI (npm install -g @azure/static-web-apps-cli).

.EXAMPLE
  ./scripts/deploy.ps1 -ResourceGroup rg-urlscanner -Location eastus2 `
      -EntraClientId <app-client-id> -EntraClientSecret <secret>
#>
param(
  [Parameter(Mandatory)] [string] $ResourceGroup,
  [string] $Location = 'eastus2',
  [string] $StaticWebAppLocation = 'eastus2',
  [string] $NamePrefix = 'urlscan',
  [Parameter(Mandatory)] [string] $EntraClientId,
  [Parameter(Mandatory)] [string] $EntraClientSecret,
  [string] $TenantId = (az account show --query tenantId -o tsv)
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Invoke-Checked([scriptblock] $Command) {
  & $Command
  if ($LASTEXITCODE -ne 0) { throw "Command failed with exit code ${LASTEXITCODE}: $Command" }
}

Write-Host '==> Creating resource group' -ForegroundColor Cyan
Invoke-Checked { az group create --name $ResourceGroup --location $Location --output none }

Write-Host '==> Deploying infrastructure (Bicep)' -ForegroundColor Cyan
$me = az ad signed-in-user show --query id -o tsv 2>$null
$outputsJson = az deployment group create `
  --resource-group $ResourceGroup `
  --template-file "$root/infra/main.bicep" `
  --parameters namePrefix=$NamePrefix staticWebAppLocation=$StaticWebAppLocation `
               entraClientId=$EntraClientId entraClientSecret=$EntraClientSecret `
               secretsAdminPrincipalId=$me `
  --query properties.outputs --output json
if ($LASTEXITCODE -ne 0) { throw 'Infrastructure deployment failed' }
$outputs = $outputsJson | ConvertFrom-Json

$functionApp = $outputs.functionAppName.value
$staticWebApp = $outputs.staticWebAppName.value

Write-Host "==> Publishing Function App $functionApp" -ForegroundColor Cyan
Push-Location "$root/api"
try {
  Invoke-Checked { npm install --omit=dev }
  Invoke-Checked { func azure functionapp publish $functionApp --javascript }
} finally {
  Pop-Location
}

Write-Host "==> Deploying Static Web App $staticWebApp" -ForegroundColor Cyan
$dist = Join-Path $root 'dist'
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
Copy-Item -Recurse "$root/frontend" $dist
$configPath = Join-Path $dist 'staticwebapp.config.json'
[System.IO.File]::WriteAllText($configPath, (Get-Content $configPath -Raw).Replace('__TENANT_ID__', $TenantId))

$token = az staticwebapp secrets list --name $staticWebApp --resource-group $ResourceGroup --query properties.apiKey -o tsv
Invoke-Checked { swa deploy $dist --deployment-token $token --env production }

Write-Host ''
Write-Host "Done. Site: $($outputs.staticWebAppUrl.value)" -ForegroundColor Green
Write-Host "Next: load API keys into Key Vault with ./scripts/set-secrets.ps1 -KeyVaultName $($outputs.keyVaultName.value)"
Write-Host "Add redirect URI $($outputs.staticWebAppUrl.value)/.auth/login/aad/callback to the Entra app registration."
