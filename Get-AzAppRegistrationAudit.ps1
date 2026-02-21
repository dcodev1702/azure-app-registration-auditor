<#
.SYNOPSIS
    Azure App Registration Auditor — reports role assignments, API permissions, and credentials
    for all Entra ID (Azure AD) application registrations in a subscription.

.DESCRIPTION
    This script enumerates all Azure AD app registrations (excluding configurable patterns),
    and for each app collects:
      - Azure RBAC role assignments (via the associated service principal)
      - API permissions (application and delegated), resolved to human-readable names
      - Credentials: client secrets (with hint) and certificates (with thumbprint),
        including expiration status (Active, EXPIRING SOON, EXPIRED)

    If multiple subscriptions are available, an interactive arrow-key menu is presented
    for subscription selection. Single-subscription tenants are used automatically.

.PARAMETER None
    This script takes no parameters. Subscription selection is interactive.

.EXAMPLE
    .\app_reg_details.ps1

    Runs the audit against the selected subscription and outputs role assignments,
    API permissions, and credentials for all app registrations.

.EXAMPLE
    .\app_reg_details.ps1 | Out-File -FilePath report.txt

    Runs the audit and saves the output to a text file.

.NOTES
    File Name : Get-AzAppRegistrationAudit.ps1
    Authors   : DCODEV1702 & Claude Opus 4.6
    Date      : 2026-02-21
    Version   : 1.0.0
    Requires  : Az PowerShell module (Az.Accounts, Az.Resources)
    Requires  : Authenticated Azure session (Connect-AzAccount)

.LINK
    https://github.com/DCODEV1702/azure-app-registration-auditor
#>

# Select subscription
$subs = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }

if ($subs.Count -eq 0) {
    Write-Host "No active Azure subscriptions found." -ForegroundColor Red
    return
}
elseif ($subs.Count -eq 1) {
    $selectedSub = $subs[0]
    Write-Host "Using subscription: $($selectedSub.Name) ($($selectedSub.Id))" -ForegroundColor Green
}
else {
    Write-Host "`nAvailable Subscriptions:" -ForegroundColor Cyan
    Write-Host "Use UP/DOWN arrow keys to highlight, then press ENTER to select.`n"

    $names = $subs | ForEach-Object { "$($_.Name) ($($_.Id))" }
    $selectedIndex = 0
    $cursorTop = [Console]::CursorTop

    [Console]::CursorVisible = $false
    try {
        while ($true) {
            # Draw menu
            [Console]::SetCursorPosition(0, $cursorTop)
            for ($i = 0; $i -lt $names.Count; $i++) {
                if ($i -eq $selectedIndex) {
                    Write-Host ("  > " + $names[$i]) -ForegroundColor Green
                } else {
                    Write-Host ("    " + $names[$i])
                }
            }

            $key = [Console]::ReadKey($true)
            switch ($key.Key) {
                'UpArrow'   { if ($selectedIndex -gt 0) { $selectedIndex-- } }
                'DownArrow' { if ($selectedIndex -lt $names.Count - 1) { $selectedIndex++ } }
                'Enter'     { break }
            }
            if ($key.Key -eq 'Enter') { break }
        }
    }
    finally {
        [Console]::CursorVisible = $true
    }

    $selectedSub = $subs[$selectedIndex]
    Write-Host "`nSelected: $($selectedSub.Name) ($($selectedSub.Id))" -ForegroundColor Green
}

Set-AzContext -Subscription $selectedSub.Id | Out-Null

# Exclude patterns
$excludeApps = @(
    "^ConnectSyncProvisioning"
)
$excludeAppsRegex = ($excludeApps -join "|")

# Cache service principal lookups for permission resolution
$spCache = @{}

# Get all app registrations, excluding matches
$apps = Get-AzADApplication | Where-Object { $_.DisplayName -notmatch $excludeAppsRegex }

$roleResults = @()
$permResults = @()
$credResults = @()

foreach ($app in $apps) {

    # --- ROLE ASSIGNMENTS ---
    $sp = Get-AzADServicePrincipal -ApplicationId $app.AppId -ErrorAction SilentlyContinue

    if ($sp) {
        $roles = Get-AzRoleAssignment -ObjectId $sp.Id -ErrorAction SilentlyContinue
        if ($roles) {
            foreach ($role in $roles) {
                $roleResults += [PSCustomObject]@{
                    AppName    = $app.DisplayName
                    AppId      = $app.AppId
                    SPObjectId = $sp.Id
                    RoleName   = $role.RoleDefinitionName
                    Scope      = $role.Scope
                }
            }
        }
    }

    # --- API PERMISSIONS ---
    foreach ($resource in $app.RequiredResourceAccess) {
        $resourceAppId = $resource.ResourceAppId

        if (-not $spCache.ContainsKey($resourceAppId)) {
            $rsp = Get-AzADServicePrincipal -Filter "appId eq '$resourceAppId'" -ErrorAction SilentlyContinue
            $spCache[$resourceAppId] = $rsp
        }
        $rsp = $spCache[$resourceAppId]
        $resourceName = if ($rsp) { $rsp.DisplayName } else { $resourceAppId }

        foreach ($perm in $resource.ResourceAccess) {
            $permName = $perm.Id
            if ($rsp) {
                $match = $rsp.AppRole | Where-Object { $_.Id -eq $perm.Id }
                if (-not $match) {
                    $match = $rsp.Oauth2PermissionScope | Where-Object { $_.Id -eq $perm.Id }
                }
                if ($match) { $permName = $match.Value }
            }

            $permResults += [PSCustomObject]@{
                AppName    = $app.DisplayName
                AppId      = $app.AppId
                Resource   = $resourceName
                Permission = $permName
                Type       = if ($perm.Type -eq 'Role') { 'Application' } else { 'Delegated' }
            }
        }
    }

    # --- CREDENTIALS (via Get-AzADAppCredential) ---
    $creds = Get-AzADAppCredential -ObjectId $app.Id -ErrorAction SilentlyContinue

    foreach ($cred in $creds) {
        $status = if ($cred.EndDateTime -lt (Get-Date)) { "EXPIRED" }
                  elseif ($cred.EndDateTime -lt (Get-Date).AddDays(30)) { "EXPIRING SOON" }
                  else { "Active" }

        # Determine type: if Hint is populated it's a secret, otherwise a certificate
        $isSecret = [bool]$cred.Hint

        $thumbprint = "N/A"
        if (-not $isSecret -and $cred.CustomKeyIdentifier) {
            try {
                $thumbprint = [System.Convert]::ToHexString($cred.CustomKeyIdentifier)
            } catch {
                $thumbprint = ($cred.CustomKeyIdentifier | ForEach-Object { '{0:X2}' -f $_ }) -join ''
            }
        }

        $credResults += [PSCustomObject]@{
            AppName     = $app.DisplayName
            AppId       = $app.AppId
            CredType    = if ($isSecret) { "Secret" } else { "Certificate" }
            Description = $cred.DisplayName
            Hint        = if ($isSecret) { $cred.Hint } else { "N/A" }
            Thumbprint  = $thumbprint
            KeyId       = $cred.KeyId
            StartDate   = $cred.StartDateTime
            ExpiresOn   = $cred.EndDateTime
            Status      = $status
        }
    }
}

# --- OUTPUT ---
Write-Host "`n=== ROLE ASSIGNMENTS ===" -ForegroundColor Cyan
if ($roleResults) { $roleResults | Sort-Object AppName | Format-Table -AutoSize }
else { Write-Host "No role assignments found." }

Write-Host "`n=== API PERMISSIONS ===" -ForegroundColor Cyan
if ($permResults) { $permResults | Sort-Object AppName, Resource | Format-Table -AutoSize }
else { Write-Host "No API permissions found." }

Write-Host "`n=== CREDENTIALS (Secrets & Certificates) ===" -ForegroundColor Cyan
if ($credResults) {
    $credResults | Sort-Object AppName, CredType |
        Format-Table AppName, AppId, CredType, Description, Hint, Thumbprint, KeyId, StartDate, ExpiresOn, Status -AutoSize -Wrap
}
else { Write-Host "No credentials found." }
