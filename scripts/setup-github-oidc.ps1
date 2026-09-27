<#
.SYNOPSIS
  One-time setup so GitHub Actions can deploy to Azure without stored credentials (OIDC).
  Creates an Entra app + service principal trusted only for pushes to main of this repo,
  grants it the minimum deploy roles, and sets the GitHub repository variables.

.PREREQUISITES
  az login (with rights to create app registrations and assign roles on the resource group),
  gh auth login, and infrastructure already deployed via ./scripts/deploy.ps1.

.EXAMPLE
  ./scripts/setup-github-oidc.ps1 -ResourceGroup rg-urlscanner -Repo securitymike/url-scanner
#>
param(
  [Parameter(Mandatory)] [string] $ResourceGroup,
  [Parameter(Mandatory)] [string] $Repo,
  [string] $Branch = 'main',
  [string] $AppName = 'url-scanner-github-deploy'
)

$ErrorActionPreference = 'Stop'

function Invoke-Az {
  $out = az @args
  if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed" }
  return $out
}

$subscriptionId = Invoke-Az account show --query id -o tsv
$tenantId = Invoke-Az account show --query tenantId -o tsv
$functionApp = Invoke-Az functionapp list -g $ResourceGroup --query '[0].name' -o tsv
$functionAppId = Invoke-Az functionapp list -g $ResourceGroup --query '[0].id' -o tsv
$staticWebApp = Invoke-Az staticwebapp list -g $ResourceGroup --query '[0].name' -o tsv
$staticWebAppId = Invoke-Az staticwebapp list -g $ResourceGroup --query '[0].id' -o tsv
if (-not $functionApp -or -not $staticWebApp) { throw "Function App / Static Web App not found in $ResourceGroup. Run deploy.ps1 first." }

Write-Host "==> Creating app registration $AppName" -ForegroundColor Cyan
$appId = Invoke-Az ad app list --display-name $AppName --query '[0].appId' -o tsv
if (-not $appId) { $appId = Invoke-Az ad app create --display-name $AppName --query appId -o tsv }
$spId = Invoke-Az ad sp list --filter "appId eq '$appId'" --query '[0].id' -o tsv
if (-not $spId) { $spId = Invoke-Az ad sp create --id $appId --query id -o tsv }

Write-Host "==> Adding federated credential for $Repo@$Branch" -ForegroundColor Cyan
$credName = "github-$($Repo -replace '[^A-Za-z0-9-]', '-')-$Branch"
$existing = Invoke-Az ad app federated-credential list --id $appId --query "[?name=='$credName'].name" -o tsv
if (-not $existing) {
  $tmp = New-TemporaryFile
  try {
    @{
      name      = $credName
      issuer    = 'https://token.actions.githubusercontent.com'
      subject   = "repo:${Repo}:ref:refs/heads/$Branch"
      audiences = @('api://AzureADTokenExchange')
    } | ConvertTo-Json | ForEach-Object { [System.IO.File]::WriteAllText($tmp.FullName, $_) }
    Invoke-Az ad app federated-credential create --id $appId --parameters "@$($tmp.FullName)" --output none
  } finally {
    Remove-Item $tmp.FullName -Force
  }
}

Write-Host '==> Assigning deploy roles (scoped to the two resources only)' -ForegroundColor Cyan
Invoke-Az role assignment create --assignee-object-id $spId --assignee-principal-type ServicePrincipal `
  --role 'Website Contributor' --scope $functionAppId --output none
Invoke-Az role assignment create --assignee-object-id $spId --assignee-principal-type ServicePrincipal `
  --role 'Contributor' --scope $staticWebAppId --output none

Write-Host "==> Setting GitHub variables on $Repo" -ForegroundColor Cyan
$vars = [ordered]@{
  AZURE_CLIENT_ID           = $appId
  AZURE_TENANT_ID           = $tenantId
  AZURE_SUBSCRIPTION_ID     = $subscriptionId
  AZURE_RESOURCE_GROUP      = $ResourceGroup
  AZURE_FUNCTION_APP_NAME   = $functionApp
  AZURE_STATIC_WEB_APP_NAME = $staticWebApp
}
foreach ($name in $vars.Keys) {
  gh variable set $name --repo $Repo --body $vars[$name]
  if ($LASTEXITCODE -ne 0) { throw "Failed to set GitHub variable $name" }
}

Write-Host 'Done. Pushes to main will now test and deploy automatically.' -ForegroundColor Green
