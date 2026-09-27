<#
.SYNOPSIS
  Stores the scanner's third-party API keys in Azure Key Vault. Press Enter to skip a key.
  Skipped providers show as "Not configured" in reports.

.EXAMPLE
  ./scripts/set-secrets.ps1 -KeyVaultName kv-urlscan-abc123
#>
param([Parameter(Mandatory)] [string] $KeyVaultName)

$ErrorActionPreference = 'Stop'

$secrets = [ordered]@{
  'google-safe-browsing-api-key' = 'Google Safe Browsing API key'
  'virustotal-api-key'           = 'VirusTotal API key'
  'urlscan-api-key'              = 'urlscan.io API key'
  'urlhaus-auth-key'             = 'abuse.ch (URLhaus) Auth-Key'
  'anthropic-api-key'            = 'Anthropic API key (Claude content classifier)'
}

foreach ($name in $secrets.Keys) {
  $secure = Read-Host -Prompt "$($secrets[$name]) [$name]" -AsSecureString
  $plain = [System.Net.NetworkCredential]::new('', $secure).Password
  if ([string]::IsNullOrWhiteSpace($plain)) {
    Write-Host "  skipped $name" -ForegroundColor DarkGray
    continue
  }
  # Pass the value via a temp file so it never appears in the process list or shell history.
  $tmp = New-TemporaryFile
  try {
    [System.IO.File]::WriteAllText($tmp.FullName, $plain)
    az keyvault secret set --vault-name $KeyVaultName --name $name --file $tmp.FullName --output none
    if ($LASTEXITCODE -ne 0) { throw "Failed to set $name" }
    Write-Host "  stored $name" -ForegroundColor Green
  } finally {
    Remove-Item $tmp.FullName -Force
  }
}
Write-Host 'Secrets are cached by the Function App for up to 10 minutes.'
