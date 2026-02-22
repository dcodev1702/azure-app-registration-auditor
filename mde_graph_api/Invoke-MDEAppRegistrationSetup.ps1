<#
.SYNOPSIS
    Creates an Entra ID app registration for the MDE Device Isolation Manager
    with all required API permissions, admin consent, and appConfig.json output.

.DESCRIPTION
    This script provisions everything needed to run mde_device_actions.ps1:

        1. Creates app registration (mde_device_manager) in Entra ID
        2. Assigns Application permissions:
            - WindowsDefenderATP: Machine.Read.All, Machine.Isolate
            - Microsoft Graph: ThreatHunting.Read.All, RoleManagement.Read.Directory
        3. Creates a service principal
        4. Grants admin consent for all permissions
        5. Creates a client secret (36-month validity)
        6. Writes appConfig.json with client_id, client_secret, tenant_id, subscription_id

.NOTES
    File Name : Invoke-MDEAppRegistrationSetup.ps1
    Authors   : DCODEV1702 & Claude Opus 4.6
    Date      : 2026-02-22
    Version   : 1.0.0
    Requires  : Az PowerShell module (Az.Accounts, Az.Resources)
    Requires  : Authenticated Azure session with admin consent permissions

.LINK
    https://github.com/DCODEV1702/azure-app-registration-auditor
#>

$ErrorActionPreference = 'Stop'

# ============================================================
# PRE-FLIGHT: Verify Azure session
# ============================================================
try {
    $ctx = Get-AzContext
    if (-not $ctx -or -not $ctx.Account) { throw "No active session" }
    Write-Host "Authenticated as: $($ctx.Account.Id) (Tenant: $($ctx.Tenant.Id))" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Not authenticated to Azure. Run Connect-AzAccount first." -ForegroundColor Red
    return
}

$tenantId       = $ctx.Tenant.Id
$subscriptionId = $ctx.Subscription.Id

# ============================================================
# CONFIGURATION
# ============================================================
$appName         = "mde_device_manager"
$secretValidMonths = 36

# Well-known API AppIds
$graphAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
$mdeAppId   = "fc780465-2017-40d4-a0c5-307022471b92"  # WindowsDefenderATP

# ============================================================
# STEP 1: Create the App Registration
# ============================================================
Write-Host "`n=== STEP 1: Creating app registration '$appName' ===" -ForegroundColor Cyan

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
# STEP 2: Look up permission IDs from service principals
# ============================================================
Write-Host "`n=== STEP 2: Resolving API permission IDs ===" -ForegroundColor Cyan

# Get Microsoft Graph service principal and resolve role IDs
$graphSp = Get-AzADServicePrincipal -Filter "appId eq '$graphAppId'"
$graphRoles = $graphSp.AppRole

$graphThreatHunting = ($graphRoles | Where-Object { $_.Value -eq 'ThreatHunting.Read.All' }).Id
$graphRoleMgmt      = ($graphRoles | Where-Object { $_.Value -eq 'RoleManagement.Read.Directory' }).Id

Write-Host "  ThreatHunting.Read.All       : $graphThreatHunting" -ForegroundColor Green
Write-Host "  RoleManagement.Read.Directory: $graphRoleMgmt" -ForegroundColor Green

# Get WindowsDefenderATP service principal and resolve role IDs
$mdeSp = Get-AzADServicePrincipal -Filter "appId eq '$mdeAppId'"
$mdeRoles = $mdeSp.AppRole

$mdeMachineRead    = ($mdeRoles | Where-Object { $_.Value -eq 'Machine.Read.All' }).Id
$mdeMachineIsolate = ($mdeRoles | Where-Object { $_.Value -eq 'Machine.Isolate' }).Id

Write-Host "  Machine.Read.All             : $mdeMachineRead" -ForegroundColor Green
Write-Host "  Machine.Isolate              : $mdeMachineIsolate" -ForegroundColor Green

# ============================================================
# STEP 3: Assign API permissions to the app registration
# ============================================================
Write-Host "`n=== STEP 3: Assigning API permissions ===" -ForegroundColor Cyan

$patchBody = @{
    requiredResourceAccess = @(
        @{
            resourceAppId  = $graphAppId
            resourceAccess = @(
                @{ id = $graphThreatHunting; type = "Role" }
                @{ id = $graphRoleMgmt;      type = "Role" }
            )
        }
        @{
            resourceAppId  = $mdeAppId
            resourceAccess = @(
                @{ id = $mdeMachineRead;    type = "Role" }
                @{ id = $mdeMachineIsolate; type = "Role" }
            )
        }
    )
} | ConvertTo-Json -Depth 10

$result = Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)" -Method PATCH -Payload $patchBody
if ($result.StatusCode -eq 204) {
    Write-Host "  API permissions assigned:" -ForegroundColor Green
    Write-Host "    - Microsoft Graph: ThreatHunting.Read.All (Application)" -ForegroundColor Green
    Write-Host "    - Microsoft Graph: RoleManagement.Read.Directory (Application)" -ForegroundColor Green
    Write-Host "    - WindowsDefenderATP: Machine.Read.All (Application)" -ForegroundColor Green
    Write-Host "    - WindowsDefenderATP: Machine.Isolate (Application)" -ForegroundColor Green
} else {
    Write-Host "  WARNING: PATCH returned HTTP $($result.StatusCode)" -ForegroundColor Yellow
}

# ============================================================
# STEP 4: Create Service Principal
# ============================================================
Write-Host "`n=== STEP 4: Creating service principal ===" -ForegroundColor Cyan

$sp = Get-AzADServicePrincipal -ApplicationId $app.AppId -ErrorAction SilentlyContinue
if (-not $sp) {
    $sp = New-AzADServicePrincipal -ApplicationId $app.AppId
    Write-Host "Service principal created: $($sp.Id)" -ForegroundColor Green
} else {
    Write-Host "Service principal already exists: $($sp.Id)" -ForegroundColor Yellow
}

# ============================================================
# STEP 5: Grant admin consent for all permissions
# ============================================================
Write-Host "`n=== STEP 5: Granting admin consent ===" -ForegroundColor Cyan

$allPermissions = @(
    @{ ResourceSp = $graphSp; RoleId = $graphThreatHunting; Name = "ThreatHunting.Read.All" }
    @{ ResourceSp = $graphSp; RoleId = $graphRoleMgmt;      Name = "RoleManagement.Read.Directory" }
    @{ ResourceSp = $mdeSp;   RoleId = $mdeMachineRead;     Name = "Machine.Read.All" }
    @{ ResourceSp = $mdeSp;   RoleId = $mdeMachineIsolate;  Name = "Machine.Isolate" }
)

# Get existing grants once
$existingResp = Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.Id)/appRoleAssignments" -Method GET
$existingGrants = ($existingResp.Content | ConvertFrom-Json).value

foreach ($perm in $allPermissions) {
    $alreadyGranted = $existingGrants | Where-Object { $_.appRoleId -eq $perm.RoleId }

    if (-not $alreadyGranted) {
        $grantBody = @{
            principalId = $sp.Id
            resourceId  = $perm.ResourceSp.Id
            appRoleId   = $perm.RoleId
        } | ConvertTo-Json

        $grantResult = Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.Id)/appRoleAssignments" -Method POST -Payload $grantBody
        if ($grantResult.StatusCode -eq 201) {
            Write-Host "  Admin consent granted: $($perm.Name)" -ForegroundColor Green
        } else {
            Write-Host "  Failed to grant $($perm.Name): HTTP $($grantResult.StatusCode)" -ForegroundColor Red
        }
    } else {
        Write-Host "  Already consented: $($perm.Name)" -ForegroundColor Yellow
    }
}

# ============================================================
# STEP 6: Create client secret
# ============================================================
Write-Host "`n=== STEP 6: Creating client secret ===" -ForegroundColor Cyan

$secretBody = @{
    passwordCredential = @{
        displayName = "mde_device_manager_secret"
        endDateTime = (Get-Date).AddMonths($secretValidMonths).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
} | ConvertTo-Json -Depth 5

$secretResponse = Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)/addPassword" -Method POST -Payload $secretBody
$secretCred = $secretResponse.Content | ConvertFrom-Json

Write-Host "  KeyId      : $($secretCred.keyId)" -ForegroundColor Green
Write-Host "  Description: $($secretCred.displayName)" -ForegroundColor Green
Write-Host "  Hint       : $($secretCred.hint)" -ForegroundColor Green
Write-Host "  Expires    : $($secretCred.endDateTime)" -ForegroundColor Green

# ============================================================
# STEP 7: Write appConfig.json
# ============================================================
Write-Host "`n=== STEP 7: Writing appConfig.json ===" -ForegroundColor Cyan

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
$configPath = Join-Path $scriptDir "appConfig.json"

if ($secretCred.secretText) {
    @{
        client_id       = $app.AppId
        client_secret   = $secretCred.secretText
        tenant_id       = $tenantId
        subscription_id = $subscriptionId
    } | ConvertTo-Json | Set-Content -Path $configPath -Encoding UTF8

    Write-Host "  Written to: $configPath" -ForegroundColor Green
    Write-Host "  >>> DO NOT commit this file to source control <<<" -ForegroundColor Red
} else {
    Write-Host "  ERROR: Secret text not returned. Check Azure Portal." -ForegroundColor Red
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  SETUP COMPLETE — $appName" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Client ID       : $($app.AppId)"
Write-Host "  Tenant ID       : $tenantId"
Write-Host "  Subscription ID : $subscriptionId"
Write-Host "  SP Object ID    : $($sp.Id)"
Write-Host ""
Write-Host "  Permissions:" -ForegroundColor Yellow
Write-Host "    Microsoft Graph  : ThreatHunting.Read.All, RoleManagement.Read.Directory"
Write-Host "    WindowsDefenderATP: Machine.Read.All, Machine.Isolate"
Write-Host ""
Write-Host "  Config file: $configPath"
Write-Host "============================================`n" -ForegroundColor Cyan
Write-Host "Run ./mde_device_actions.ps1 to manage MDE devices.`n" -ForegroundColor Green
