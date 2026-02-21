<#
.SYNOPSIS
    Sets up an Entra ID App Registration with secret + certificate auth against
    an Entra ID-only storage account for auditor demonstration purposes as a DFIR Demo (PoC).

.DESCRIPTION
    This script:
        1. Generates a self-signed certificate (public + private key) and exports to PFX
        2. Creates an app registration 'demo_dfir_app' in Entra ID
        3. Uploads the certificate (public key) to the app registration
        4. Creates a client secret on the app registration
        5. Creates a storage account 'demodfirsa007' with:
            - Entra ID-only authentication (shared key disabled, anonymous access off)
            - Blob service only
        6. Creates a service principal and assigns Storage Blob Data Contributor role
        7. Demonstrates authentication using both certificate and secret

.NOTES
    File Name : New-DemoDfirAppSetup.ps1
    Authors   : DCODEV1702 & Claude Opus 4.6
    Date      : 2026-02-21
    Version   : 1.0.0
    Requires  : Az PowerShell module (Az.Accounts, Az.Resources, Az.Storage)
    Requires  : Authenticated Azure session (Connect-AzAccount)

.LINK
    https://github.com/DCODEV1702/azure-app-registration-auditor
#>

# ============================================================
# CONFIGURATION — adjust these as needed
# ============================================================
$appName          = "demo_dfir_app"
$certName         = "DemoDfirCert"
$certOutputDir    = $PSScriptRoot  # Where cert files are saved
$pfxPassword      = "#Dem0.Df!r_2026!" # PFX export password
$certValidMonths  = 36

$storageAcctName  = "demodfirsa007"
$resourceGroup    = "rg-demo-dfir"
$location         = "eastus2"

# ============================================================
# STEP 1: Generate self-signed certificate + export PFX/CER
# ============================================================
Write-Host "`n=== STEP 1: Generating self-signed certificate ===" -ForegroundColor Cyan

$certSubject = "CN=$certName"
$certPfxPath = Join-Path $certOutputDir "$certName.pfx"
$certCerPath = Join-Path $certOutputDir "$certName.cer"

# Create self-signed cert in CurrentUser\My store
$cert = New-SelfSignedCertificate `
    -Subject $certSubject `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddMonths($certValidMonths)

Write-Host "Certificate created: $($cert.Subject)" -ForegroundColor Green
Write-Host "Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green

# Export PFX (private + public key) — for YOUR use when authenticating
$pfxSecure = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $certPfxPath -Password $pfxSecure | Out-Null
Write-Host "PFX exported to: $certPfxPath" -ForegroundColor Green

# Export CER (public key only) — this is what gets uploaded to the app registration
Export-Certificate -Cert $cert -FilePath $certCerPath | Out-Null
Write-Host "CER exported to: $certCerPath" -ForegroundColor Green

# ============================================================
# STEP 2: Create the App Registration
# ============================================================
Write-Host "`n=== STEP 2: Creating app registration '$appName' ===" -ForegroundColor Cyan

# Check if it already exists
$existingApp = Get-AzADApplication -DisplayName $appName -ErrorAction SilentlyContinue
if ($existingApp) {
    Write-Host "App registration '$appName' already exists (AppId: $($existingApp.AppId)). Using existing." -ForegroundColor Yellow
    $app = $existingApp
} else {
    $app = New-AzADApplication -DisplayName $appName
    Write-Host "App registration created." -ForegroundColor Green
}

Write-Host "  Application (client) ID : $($app.AppId)" -ForegroundColor Green
Write-Host "  Object ID               : $($app.Id)" -ForegroundColor Green

# ============================================================
# STEP 3: Upload the certificate to the app registration
# ============================================================
Write-Host "`n=== STEP 3: Uploading certificate to app registration ===" -ForegroundColor Cyan

# Read the .cer file as base64 for the credential
$certBytes = [System.IO.File]::ReadAllBytes($certCerPath)
$certBase64 = [System.Convert]::ToBase64String($certBytes)

# Add the certificate credential
$certCred = New-AzADAppCredential `
    -ApplicationId $app.AppId `
    -CertValue $certBase64 `
    -StartDate $cert.NotBefore `
    -EndDate $cert.NotAfter

Write-Host "Certificate uploaded to app registration." -ForegroundColor Green
Write-Host "  KeyId     : $($certCred.KeyId)" -ForegroundColor Green
Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
Write-Host "  Expires   : $($cert.NotAfter)" -ForegroundColor Green

# ============================================================
# STEP 4: Create a client secret on the app registration
# ============================================================
Write-Host "`n=== STEP 4: Creating client secret ===" -ForegroundColor Cyan

$secretCred = New-AzADAppCredential `
    -ApplicationId $app.AppId `
    -StartDate (Get-Date) `
    -EndDate (Get-Date).AddMonths($certValidMonths)

Write-Host "Client secret created." -ForegroundColor Green
Write-Host "  KeyId      : $($secretCred.KeyId)" -ForegroundColor Green
Write-Host "  Secret Hint: $($secretCred.Hint)" -ForegroundColor Green
Write-Host "  Expires    : $($secretCred.EndDateTime)" -ForegroundColor Green

# IMPORTANT: Save the secret value now — it cannot be retrieved later
if ($secretCred.SecretText) {
    Write-Host "  SECRET VALUE: $($secretCred.SecretText)" -ForegroundColor Yellow
    Write-Host "  >>> SAVE THIS NOW — it will NOT be shown again <<<" -ForegroundColor Red
    $clientSecret = $secretCred.SecretText
} else {
    Write-Host "  (SecretText not returned — check Azure Portal for the value)" -ForegroundColor DarkYellow
}

# ============================================================
# STEP 5: Create Service Principal for the app
# ============================================================
Write-Host "`n=== STEP 5: Creating service principal ===" -ForegroundColor Cyan

$sp = Get-AzADServicePrincipal -ApplicationId $app.AppId -ErrorAction SilentlyContinue
if (-not $sp) {
    $sp = New-AzADServicePrincipal -ApplicationId $app.AppId
    Write-Host "Service principal created: $($sp.Id)" -ForegroundColor Green
} else {
    Write-Host "Service principal already exists: $($sp.Id)" -ForegroundColor Yellow
}

# ============================================================
# STEP 6: Create resource group + storage account (Entra ID only)
# ============================================================
Write-Host "`n=== STEP 6: Creating storage account '$storageAcctName' ===" -ForegroundColor Cyan

# Create resource group if it doesn't exist
$rg = Get-AzResourceGroup -Name $resourceGroup -ErrorAction SilentlyContinue
if (-not $rg) {
    $rg = New-AzResourceGroup -Name $resourceGroup -Location $location
    Write-Host "Resource group '$resourceGroup' created." -ForegroundColor Green
} else {
    Write-Host "Resource group '$resourceGroup' already exists." -ForegroundColor Yellow
}

# Create storage account with Entra ID-only auth
$sa = Get-AzStorageAccount -ResourceGroupName $resourceGroup -Name $storageAcctName -ErrorAction SilentlyContinue
if (-not $sa) {
    $sa = New-AzStorageAccount `
        -ResourceGroupName $resourceGroup `
        -Name $storageAcctName `
        -Location $location `
        -SkuName "Standard_LRS" `
        -Kind "StorageV2" `
        -AllowBlobPublicAccess $false `
        -AllowSharedKeyAccess $false `
        -MinimumTlsVersion "TLS1_2"

    Write-Host "Storage account created with Entra ID-only auth." -ForegroundColor Green
} else {
    # Ensure settings are correct on existing account
    Set-AzStorageAccount `
        -ResourceGroupName $resourceGroup `
        -Name $storageAcctName `
        -AllowBlobPublicAccess $false `
        -AllowSharedKeyAccess $false | Out-Null
    Write-Host "Storage account '$storageAcctName' already exists. Settings enforced." -ForegroundColor Yellow
}

Write-Host "  Anonymous access : Disabled" -ForegroundColor Green
Write-Host "  Shared key access: Disabled (Entra ID only)" -ForegroundColor Green
Write-Host "  Minimum TLS      : 1.2" -ForegroundColor Green

# ============================================================
# STEP 7: Assign Storage Blob Data Contributor role to the app
# ============================================================
Write-Host "`n=== STEP 7: Assigning Storage Blob Data Contributor role ===" -ForegroundColor Cyan

$roleScope = $sa.Id
$existingRole = Get-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName "Storage Blob Data Contributor" -Scope $roleScope -ErrorAction SilentlyContinue

if (-not $existingRole) {
    New-AzRoleAssignment `
        -ObjectId $sp.Id `
        -RoleDefinitionName "Storage Blob Data Contributor" `
        -Scope $roleScope | Out-Null
    Write-Host "Role 'Storage Blob Data Contributor' assigned to '$appName' on '$storageAcctName'." -ForegroundColor Green
} else {
    Write-Host "Role assignment already exists." -ForegroundColor Yellow
}

# ============================================================
# STEP 8: Create a demo blob container
# ============================================================
Write-Host "`n=== STEP 8: Creating demo blob container ===" -ForegroundColor Cyan

# Use the current user's context (not the app) to create the container
$ctx = New-AzStorageContext -StorageAccountName $storageAcctName -UseConnectedAccount
$containerName = "demo-dfir-container"

$existingContainer = Get-AzStorageContainer -Name $containerName -Context $ctx -ErrorAction SilentlyContinue
if (-not $existingContainer) {
    New-AzStorageContainer -Name $containerName -Context $ctx -Permission Off | Out-Null
    Write-Host "Container '$containerName' created (private access)." -ForegroundColor Green
} else {
    Write-Host "Container '$containerName' already exists." -ForegroundColor Yellow
}

# ============================================================
# SUMMARY
# ============================================================
$tenantId = (Get-AzContext).Tenant.Id

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  SETUP COMPLETE — SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  App Name       : $appName"
Write-Host "  Client ID      : $($app.AppId)"
Write-Host "  Tenant ID      : $tenantId"
Write-Host "  Object ID      : $($app.Id)"
Write-Host "  SP Object ID   : $($sp.Id)"
Write-Host ""
Write-Host "  Certificate    : $certPfxPath"
Write-Host "  Thumbprint     : $($cert.Thumbprint)"
Write-Host "  PFX Password   : $pfxPassword"
Write-Host ""
Write-Host "  Storage Account: $storageAcctName"
Write-Host "  Resource Group : $resourceGroup"
Write-Host "  Container      : $containerName"
Write-Host "  Auth Mode      : Entra ID only (shared key disabled)"
Write-Host "============================================`n" -ForegroundColor Cyan

# ============================================================
# AUTHENTICATION EXAMPLES
# ============================================================
Write-Host "=== HOW TO AUTHENTICATE ===" -ForegroundColor Yellow

Write-Host "`n--- Option A: Certificate-Based Auth ---" -ForegroundColor Cyan
Write-Host @"
Connect-AzAccount ``
    -ServicePrincipal ``
    -ApplicationId '$($app.AppId)' ``
    -TenantId '$tenantId' ``
    -CertificateThumbprint '$($cert.Thumbprint)'
"@ -ForegroundColor White

Write-Host "`n--- Option B: Client Secret Auth ---" -ForegroundColor Cyan
Write-Host @"
`$secureSecret = ConvertTo-SecureString 'INSERT_YOUR_CLIENT_SECRET_HERE' -AsPlainText -Force
`$credential = New-Object System.Management.Automation.PSCredential('$($app.AppId)', `$secureSecret)
Connect-AzAccount ``
    -ServicePrincipal ``
    -Credential `$credential ``
    -TenantId '$tenantId'
"@ -ForegroundColor White

Write-Host "`n--- After authenticating, access the storage account ---" -ForegroundColor Cyan
Write-Host @"
`$ctx = New-AzStorageContext -StorageAccountName '$storageAcctName' -UseConnectedAccount
Get-AzStorageBlob -Container '$containerName' -Context `$ctx
"@ -ForegroundColor White

Write-Host "`nNow run .\Get-AzAppRegistrationAudit.ps1 to see this app's secret AND certificate in the audit output!`n" -ForegroundColor Green
