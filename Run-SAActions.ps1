<#
.SYNOPSIS
    Simulates service principal activity against the demo DFIR storage account
    using both certificate and client secret authentication.

.DESCRIPTION
    This script authenticates as the demo_dfir_app service principal using both
    credential types (certificate and secret), then performs storage operations
    that generate forensic artifacts in AADServicePrincipalSignInLogs and
    StorageBlobLogs:

        1. Connects via Certificate-Based Auth — lists blobs
        2. Connects via Client Secret Auth — lists blobs
        3. Creates and uploads a timestamped marker file ("PEEKA-BOO, I SEE U!")
        4. Creates a FY26_QTR_Reports directory with fictitious financial data (CSV)

    All actions are performed as the app registration's service principal,
    generating distinct AuthenticationHash values per credential type for
    forensic correlation.

.NOTES
    File Name : Run-SAActions.ps1
    Authors   : DCODEV1702 & Claude Opus 4.6
    Date      : 2026-02-22
    Version   : 1.0.0
    Requires  : Az PowerShell module (Az.Accounts, Az.Storage)
    Requires  : appRegSec.json (created by Invoke-DemoDfirAppSetup.ps1)
    Requires  : DemoDfirCert imported in Cert:\CurrentUser\My

.LINK
    https://github.com/DCODEV1702/azure-app-registration-auditor
#>

$ErrorActionPreference = 'Stop'

# ============================================================
# CONFIGURATION
# ============================================================
$storageAcctName = "demodfirsa007"
$containerName   = "demo-dfir-container"
$timestamp       = Get-Date -Format "yyyyMMdd_HHmmss"

# Read app registration credentials from JSON
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
$appRegSecPath = Join-Path $scriptDir "appRegSec.json"
if (-not (Test-Path $appRegSecPath)) {
    Write-Host "ERROR: appRegSec.json not found. Run Invoke-DemoDfirAppSetup.ps1 first." -ForegroundColor Red
    return
}
$appRegSec = Get-Content $appRegSecPath | ConvertFrom-Json
$clientId  = $appRegSec.client_id
$tenantId  = $appRegSec.tenant_id

if (-not $tenantId) {
    # Try to get tenant ID from a quick login
    Write-Host "No Az context found. Attempting cert auth to discover tenant..." -ForegroundColor Yellow
    $tenantId = Read-Host "Enter your Tenant ID"
}

# Find the certificate thumbprint in the local cert store
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=DemoDfirCert" } | Select-Object -First 1
if (-not $cert) {
    Write-Host "ERROR: DemoDfirCert not found in Cert:\CurrentUser\My. Import the PFX first." -ForegroundColor Red
    return
}
$thumbprint = $cert.Thumbprint

# ============================================================
# ACTION 1: Connect via Certificate and list blobs
# ============================================================
Write-Host "=== ACTION 1: Certificate-Based Auth ===" -ForegroundColor Cyan

Connect-AzAccount `
    -ServicePrincipal `
    -ApplicationId $clientId `
    -TenantId $tenantId `
    -CertificateThumbprint $thumbprint | Out-Null

Write-Host "  Authenticated via certificate." -ForegroundColor Green

# Resolve the app registration display name dynamically
$spInfo = Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$clientId')?`$select=displayName" -Method GET -ErrorAction SilentlyContinue
$appDisplayName = if ($spInfo -and $spInfo.StatusCode -eq 200) {
    ($spInfo.Content | ConvertFrom-Json).displayName
} else { $clientId }

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  Service Principal Actions — $appDisplayName" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Client ID  : $clientId"
Write-Host "  Tenant ID  : $tenantId"
Write-Host "  Thumbprint : $thumbprint"
Write-Host "  Storage    : $storageAcctName"
Write-Host "  Container  : $containerName"
Write-Host "============================================`n" -ForegroundColor Cyan

$ctx = New-AzStorageContext -StorageAccountName $storageAcctName -UseConnectedAccount
$blobs = Get-AzStorageBlob -Container $containerName -Context $ctx -ErrorAction SilentlyContinue
Write-Host "  Blobs in container: $(if ($blobs) { $blobs.Count } else { 0 })" -ForegroundColor Green

# Disconnect cert session
Disconnect-AzAccount | Out-Null

# ============================================================
# ACTION 2: Connect via Client Secret and list blobs
# ============================================================
Write-Host "`n=== ACTION 2: Client Secret Auth ===" -ForegroundColor Cyan

$secureSecret = ConvertTo-SecureString $appRegSec.client_secret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)
Connect-AzAccount `
    -ServicePrincipal `
    -Credential $credential `
    -TenantId $tenantId | Out-Null

Write-Host "  Authenticated via client secret." -ForegroundColor Green

$ctx = New-AzStorageContext -StorageAccountName $storageAcctName -UseConnectedAccount
$blobs = Get-AzStorageBlob -Container $containerName -Context $ctx -ErrorAction SilentlyContinue
Write-Host "  Blobs in container: $(if ($blobs) { $blobs.Count } else { 0 })" -ForegroundColor Green

# ============================================================
# ACTION 3: Create and upload marker file
# ============================================================
Write-Host "`n=== ACTION 3: Upload marker file ===" -ForegroundColor Cyan

$markerFileName = "justmemyselfandi_${timestamp}.txt"
$markerFilePath = Join-Path $env:TEMP $markerFileName
$markerContent  = "PEEKA-BOO, I SEE U! - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC)"

Set-Content -Path $markerFilePath -Value $markerContent -Encoding UTF8
Write-Host "  Created: $markerFileName" -ForegroundColor Green

# Upload to blob container
Set-AzStorageBlobContent `
    -Container $containerName `
    -File $markerFilePath `
    -Blob $markerFileName `
    -Context $ctx `
    -Force | Out-Null

Write-Host "  Uploaded to: $storageAcctName/$containerName/$markerFileName" -ForegroundColor Green

# Clean up local temp file
Remove-Item $markerFilePath -Force

# ============================================================
# ACTION 4: Create FY26_QTR_Reports directory with financial CSV
# ============================================================
Write-Host "`n=== ACTION 4: Upload FY26 Quarterly Reports ===" -ForegroundColor Cyan

$reportDir  = "FY26_QTR_Reports"
$csvFileName = "FY26_Quarterly_Revenue.csv"
$csvFilePath = Join-Path $env:TEMP $csvFileName

# Generate fictitious financial data
$financialData = @(
    [PSCustomObject]@{ Quarter="Q1"; Region="North America"; Revenue=4250000; COGS=2125000; GrossProfit=2125000; OpEx=850000; NetIncome=1275000 }
    [PSCustomObject]@{ Quarter="Q1"; Region="EMEA";          Revenue=3180000; COGS=1590000; GrossProfit=1590000; OpEx=636000; NetIncome=954000  }
    [PSCustomObject]@{ Quarter="Q1"; Region="APAC";          Revenue=2740000; COGS=1370000; GrossProfit=1370000; OpEx=548000; NetIncome=822000  }
    [PSCustomObject]@{ Quarter="Q2"; Region="North America"; Revenue=4680000; COGS=2340000; GrossProfit=2340000; OpEx=936000; NetIncome=1404000 }
    [PSCustomObject]@{ Quarter="Q2"; Region="EMEA";          Revenue=3410000; COGS=1705000; GrossProfit=1705000; OpEx=682000; NetIncome=1023000 }
    [PSCustomObject]@{ Quarter="Q2"; Region="APAC";          Revenue=2950000; COGS=1475000; GrossProfit=1475000; OpEx=590000; NetIncome=885000  }
    [PSCustomObject]@{ Quarter="Q3"; Region="North America"; Revenue=5120000; COGS=2560000; GrossProfit=2560000; OpEx=1024000; NetIncome=1536000 }
    [PSCustomObject]@{ Quarter="Q3"; Region="EMEA";          Revenue=3690000; COGS=1845000; GrossProfit=1845000; OpEx=738000; NetIncome=1107000 }
    [PSCustomObject]@{ Quarter="Q3"; Region="APAC";          Revenue=3210000; COGS=1605000; GrossProfit=1605000; OpEx=642000; NetIncome=963000  }
    [PSCustomObject]@{ Quarter="Q4"; Region="North America"; Revenue=5580000; COGS=2790000; GrossProfit=2790000; OpEx=1116000; NetIncome=1674000 }
    [PSCustomObject]@{ Quarter="Q4"; Region="EMEA";          Revenue=4020000; COGS=2010000; GrossProfit=2010000; OpEx=804000; NetIncome=1206000 }
    [PSCustomObject]@{ Quarter="Q4"; Region="APAC";          Revenue=3480000; COGS=1740000; GrossProfit=1740000; OpEx=696000; NetIncome=1044000 }
)

$financialData | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
Write-Host "  Created: $csvFileName ($(($financialData | Measure-Object).Count) rows)" -ForegroundColor Green

# Upload to blob container under FY26_QTR_Reports/ directory
$blobPath = "$reportDir/$csvFileName"
Set-AzStorageBlobContent `
    -Container $containerName `
    -File $csvFilePath `
    -Blob $blobPath `
    -Context $ctx `
    -Force | Out-Null

Write-Host "  Uploaded to: $storageAcctName/$containerName/$blobPath" -ForegroundColor Green

# Clean up local temp file
Remove-Item $csvFilePath -Force

# ============================================================
# SUMMARY
# ============================================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  ALL ACTIONS COMPLETE" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# List all blobs in the container
Write-Host "`n  Blobs in $containerName`:" -ForegroundColor Yellow
$allBlobs = Get-AzStorageBlob -Container $containerName -Context $ctx
foreach ($b in $allBlobs) {
    Write-Host "    - $($b.Name) ($([math]::Round($b.Length / 1KB, 1)) KB)" -ForegroundColor White
}

# Download and display the marker file contents
Write-Host "`n  Contents of $markerFileName`:" -ForegroundColor Yellow
$downloadPath = Join-Path $env:TEMP "download_$markerFileName"
Get-AzStorageBlobContent -Container $containerName -Blob $markerFileName -Destination $downloadPath -Context $ctx -Force | Out-Null
$fileContent = Get-Content $downloadPath -Raw
Write-Host "    $fileContent" -ForegroundColor Magenta
Remove-Item $downloadPath -Force

Write-Host "`n  Check AADServicePrincipalSignInLogs for two distinct" -ForegroundColor Yellow
Write-Host "  ClientCredentialType entries (Certificate & ClientSecret)" -ForegroundColor Yellow
Write-Host "  and correlate with StorageBlobLogs using AuthenticationHash.`n" -ForegroundColor Yellow

# Disconnect
Disconnect-AzAccount | Out-Null
Write-Host "Disconnected $appDisplayName ($clientId)." -ForegroundColor Green
