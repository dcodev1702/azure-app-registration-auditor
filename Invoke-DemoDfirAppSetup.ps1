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
    File Name : Invoke-DemoDfirAppSetup.ps1
    Authors   : DCODEV1702 & Claude Opus 4.6
    Date      : 2026-02-21
    Version   : 1.0.0
    Requires  : Az PowerShell module (Az.Accounts, Az.Resources, Az.Storage)
    Requires  : Authenticated Azure session (Connect-AzAccount)

.LINK
    https://github.com/DCODEV1702/azure-app-registration-auditor
#>

# ============================================================
# ============================================================
# PRE-FLIGHT: Verify Azure session is active
# ============================================================
$ErrorActionPreference = 'Stop'

try {
    $ctx = Get-AzContext
    if (-not $ctx -or -not $ctx.Account) { throw "No active session" }
    Write-Host "Authenticated as: $($ctx.Account.Id) (Tenant: $($ctx.Tenant.Id))" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Not authenticated to Azure. Run Connect-AzAccount first." -ForegroundColor Red
    return
}

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
# STEP 2b: Add Microsoft Graph API Application permissions
# ============================================================
Write-Host "`n=== STEP 2b: Adding Microsoft Graph API permissions ===" -ForegroundColor Cyan

# Microsoft Graph well-known AppId
$graphAppId = "00000003-0000-0000-c000-000000000000"

# Application (Role) permission IDs for Microsoft Graph
$graphPermissions = @(
    @{ Id = "b0afded3-3588-46d8-8b3d-9842eff778da"; Name = "AuditLog.Read.All" }
    @{ Id = "72f0655d-6228-4ddc-8e1b-164973b9213b"; Name = "CopilotPackages.Read.All" }
    @{ Id = "7438b122-aefc-4978-80ed-43db9fcc7715"; Name = "Device.Read.All" }
    @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Name = "Directory.Read.All" }
    @{ Id = "dd98c7f5-2d42-42d3-a0e4-633161547251"; Name = "ThreatHunting.Read.All" }
    @{ Id = "df021288-bdef-4463-88db-98f22de89214"; Name = "User.Read.All" }
)

# Build the resourceAccess array (Graph API requires camelCase: id, type)
$resourceAccessList = $graphPermissions | ForEach-Object {
    @{ id = $_.Id; type = "Role" }
}

# Use Invoke-AzRestMethod to PATCH the application with the required permissions
$patchBody = @{
    requiredResourceAccess = @(
        @{
            resourceAppId  = $graphAppId
            resourceAccess = $resourceAccessList
        }
    )
} | ConvertTo-Json -Depth 10

Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)" -Method PATCH -Payload $patchBody | Out-Null

Write-Host "  Graph API permissions added:" -ForegroundColor Green
foreach ($p in $graphPermissions) {
    Write-Host "    - $($p.Name) (Application)" -ForegroundColor Green
}

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

# Use Graph API to create the secret so we can set a displayName
$secretBody = @{
    passwordCredential = @{
        displayName = "demo_dfir_app_secret"
        endDateTime = (Get-Date).AddMonths($certValidMonths).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
} | ConvertTo-Json -Depth 5

$secretResponse = Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)/addPassword" -Method POST -Payload $secretBody
$secretCred = $secretResponse.Content | ConvertFrom-Json

Write-Host "Client secret created." -ForegroundColor Green
Write-Host "  KeyId      : $($secretCred.keyId)" -ForegroundColor Green
Write-Host "  Description: $($secretCred.displayName)" -ForegroundColor Green
Write-Host "  Secret Hint: $($secretCred.hint)" -ForegroundColor Green
Write-Host "  Expires    : $($secretCred.endDateTime)" -ForegroundColor Green

# IMPORTANT: Save the secret value now — it cannot be retrieved later
$appRegSecPath = Join-Path $PSScriptRoot "appRegSec.json"
if ($secretCred.secretText) {
    $clientSecret = $secretCred.secretText

    # Write client secret, client ID, and tenant ID to JSON for later use
    @{
        client_secret = $clientSecret
        client_id     = $app.AppId
        tenant_id     = (Get-AzContext).Tenant.Id
    } | ConvertTo-Json | Set-Content -Path $appRegSecPath -Encoding UTF8

    Write-Host "  Secret written to: $appRegSecPath" -ForegroundColor Green
    Write-Host "  >>> DO NOT commit this file to source control <<<" -ForegroundColor Red
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
# STEP 5b: Grant admin consent for Microsoft Graph permissions
# ============================================================
Write-Host "`n=== STEP 5b: Granting admin consent for Graph API permissions ===" -ForegroundColor Cyan

# Get the Microsoft Graph service principal in the tenant
$graphSp = Get-AzADServicePrincipal -Filter "appId eq '$graphAppId'" -ErrorAction SilentlyContinue

if ($graphSp) {
    foreach ($perm in $graphPermissions) {
        # Check if already granted
        $existing = Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.Id)/appRoleAssignments" -Method GET
        $existingGrants = ($existing.Content | ConvertFrom-Json).value
        $alreadyGranted = $existingGrants | Where-Object { $_.appRoleId -eq $perm.Id }

        if (-not $alreadyGranted) {
            $grantBody = @{
                principalId = $sp.Id
                resourceId  = $graphSp.Id
                appRoleId   = $perm.Id
            } | ConvertTo-Json

            $result = Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.Id)/appRoleAssignments" -Method POST -Payload $grantBody
            if ($result.StatusCode -eq 201) {
                Write-Host "  Admin consent granted: $($perm.Name)" -ForegroundColor Green
            } else {
                Write-Host "  Failed to grant $($perm.Name): HTTP $($result.StatusCode)" -ForegroundColor Red
            }
        } else {
            Write-Host "  Already consented: $($perm.Name)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "  Microsoft Graph service principal not found in tenant." -ForegroundColor Red
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

# Create storage account with Entra ID-only auth + ADLSv2 (hierarchical namespace)
$sa = Get-AzStorageAccount -ResourceGroupName $resourceGroup -Name $storageAcctName -ErrorAction SilentlyContinue
if (-not $sa) {
    $sa = New-AzStorageAccount `
        -ResourceGroupName $resourceGroup `
        -Name $storageAcctName `
        -Location $location `
        -SkuName "Standard_LRS" `
        -Kind "StorageV2" `
        -EnableHierarchicalNamespace $true `
        -AllowBlobPublicAccess $false `
        -AllowSharedKeyAccess $false `
        -MinimumTlsVersion "TLS1_2"

    # Note: File, Queue, and Table services cannot be individually disabled on StorageV2.
    # However, with shared key access disabled, only Entra ID (OAuth) auth works —
    # and the RBAC role (Storage Blob Data Contributor) only grants blob access.
    # File, Queue, and Table are effectively inaccessible.

    Write-Host "Storage account created with Entra ID-only auth + ADLSv2 (blob only)." -ForegroundColor Green
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

Write-Host "`n--- Option B: Client Secret Auth (reads from appRegSec.json) ---" -ForegroundColor Cyan
Write-Host @"
`$appRegSec = Get-Content './appRegSec.json' | ConvertFrom-Json
`$secureSecret = ConvertTo-SecureString `$appRegSec.client_secret -AsPlainText -Force
`$credential = New-Object System.Management.Automation.PSCredential(`$appRegSec.client_id, `$secureSecret)
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
