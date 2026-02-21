<#
.SYNOPSIS
    Entra ID User to Azure Role Audit — maps all Entra ID (Azure AD) users to their
    Azure RBAC role assignments.

.DESCRIPTION
    This script retrieves all Entra ID users and all Azure RBAC role assignments
    across every scope. It correlates each user to their assigned roles, producing
    a consolidated report showing:
        - User display name and UPN
        - Assigned role name (or "No Role Assigned" if none)
        - Role scope (subscription, resource group, or resource level)
        - Entra ID directory roles (if any)

    Users with multiple role assignments will appear once per role.

    Results are displayed in the console and exported to a timestamped CSV file.

    If multiple subscriptions are available, an interactive arrow-key menu is presented
    for subscription selection. Single-subscription tenants are used automatically.

    Performance: Role assignments are indexed via hashtable for fast O(1) lookups
    per user instead of linear filtering.

.PARAMETER None
    This script takes no parameters. Subscription selection is interactive.

.EXAMPLE
    .\Get-EntraIDUser2AzureRoleAudit.ps1

    Lists all Entra ID users and their Azure RBAC role assignments, and exports
    the results to a CSV file in the current directory.

.EXAMPLE
    .\Get-EntraIDUser2AzureRoleAudit.ps1 | Out-File -FilePath user-role-report.txt

    Saves the console output to a text file (CSV is also generated automatically).

.NOTES
    File Name : Get-EntraIDUser2AzureRoleAudit.ps1
    Authors   : DCODEV1702 & Claude Opus 4.6
    Date      : 2026-02-21
    Version   : 1.1.0
    Requires  : Az PowerShell module (Az.Accounts, Az.Resources)
    Requires  : Authenticated Azure session (Connect-AzAccount)

.LINK
    https://github.com/DCODEV1702/azure-app-registration-auditor
#>

# --- Subscription Selection ---
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
$subName = $selectedSub.Name
$subId   = $selectedSub.Id

# --- Entra ID Directory Roles ---
# Well-known role template IDs
$directoryRolesToCheck = @(
    @{ Name = 'Global Administrator';  TemplateId = '62e90394-69f5-4237-9190-012177145e10' }
    @{ Name = 'User Administrator';    TemplateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1' }
)

# Hashtable: UPN -> list of Entra directory role names (for CSV enrichment)
$directoryRoleLookup = @{}

foreach ($dirRole in $directoryRolesToCheck) {
    Write-Host "`nChecking $($dirRole.Name)s..." -ForegroundColor Cyan
    $response = Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=$($dirRole.TemplateId)/members" -Method GET -ErrorAction SilentlyContinue
    if ($response -and $response.StatusCode -eq 200) {
        $members = ($response.Content | ConvertFrom-Json).value
        Write-Host "$($dirRole.Name)s ($($members.Count)):" -ForegroundColor Yellow
        foreach ($member in $members) {
            Write-Host "  - $($member.displayName) ($($member.userPrincipalName))" -ForegroundColor Yellow
            $upn = $member.userPrincipalName
            if ($upn) {
                if (-not $directoryRoleLookup.ContainsKey($upn)) {
                    $directoryRoleLookup[$upn] = [System.Collections.Generic.List[string]]::new()
                }
                $directoryRoleLookup[$upn].Add($dirRole.Name)
            }
        }
    } else {
        Write-Host "Unable to retrieve $($dirRole.Name)s (insufficient permissions or role not activated)." -ForegroundColor DarkYellow
    }
}

# --- Subscription-Level Contributors ---
Write-Host "`nChecking Subscription-Level Contributors..." -ForegroundColor Cyan

# --- Retrieve all Entra ID users ---
Write-Host "`nRetrieving Entra ID users..." -ForegroundColor Cyan
$users = Get-AzADUser
Write-Host "Found $($users.Count) users." -ForegroundColor Green

# --- Retrieve all role assignments and build hashtable for O(1) lookups ---
Write-Host "Retrieving role assignments..." -ForegroundColor Cyan
$roleAssignments = Get-AzRoleAssignment
Write-Host "Found $($roleAssignments.Count) role assignments." -ForegroundColor Green

$roleLookup = @{}
foreach ($ra in $roleAssignments) {
    if (-not $roleLookup.ContainsKey($ra.ObjectId)) {
        $roleLookup[$ra.ObjectId] = [System.Collections.Generic.List[object]]::new()
    }
    $roleLookup[$ra.ObjectId].Add($ra)
}

# Display subscription-level Contributors and build lookup set
$subScope = "/subscriptions/$subId"
$subContributors = $roleAssignments | Where-Object { $_.RoleDefinitionName -eq 'Contributor' -and $_.Scope -eq $subScope }
$subContributorIds = [System.Collections.Generic.HashSet[string]]::new()
if ($subContributors) {
    Write-Host "Subscription-Level Contributors ($($subContributors.Count)):" -ForegroundColor Yellow
    foreach ($c in $subContributors) {
        Write-Host "  - $($c.DisplayName) ($($c.ObjectType))" -ForegroundColor Yellow
        [void]$subContributorIds.Add($c.ObjectId)
    }
} else {
    Write-Host "No Contributors at subscription scope." -ForegroundColor DarkYellow
}

# --- Match users to their roles ---
Write-Host "`nCorrelating users to roles...`n" -ForegroundColor Cyan

$results = foreach ($user in $users) {
    $roles = $roleLookup[$user.Id]

    $entraRoles = if ($directoryRoleLookup.ContainsKey($user.UserPrincipalName)) {
        $directoryRoleLookup[$user.UserPrincipalName] -join '; '
    } else { '' }

    $isSubContributor = if ($subContributorIds.Contains($user.Id)) { 'Yes' } else { 'No' }

    if ($roles) {
        foreach ($role in $roles) {
            [PSCustomObject]@{
                Subscription       = $subName
                SubscriptionId     = $subId
                DisplayName        = $user.DisplayName
                UPN                = $user.UserPrincipalName
                EntraDirectoryRole = $entraRoles
                SubLevelContributor = $isSubContributor
                RoleName           = $role.RoleDefinitionName
                Scope              = $role.Scope
            }
        }
    } else {
        [PSCustomObject]@{
            Subscription       = $subName
            SubscriptionId     = $subId
            DisplayName        = $user.DisplayName
            UPN                = $user.UserPrincipalName
            EntraDirectoryRole = $entraRoles
            SubLevelContributor = $isSubContributor
            RoleName           = "No Role Assigned"
            Scope              = "N/A"
        }
    }
}

$results = $results | Sort-Object DisplayName

# --- Output to console ---
$results | Format-Table -AutoSize

# --- Export to CSV ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# User-to-role mapping CSV
$csvPath = Join-Path $PSScriptRoot "EntraID_User_Role_Audit_$timestamp.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "`nCSV exported to: $csvPath" -ForegroundColor Green

# Raw role assignments CSV
$rawRoleCsv = Join-Path $PSScriptRoot "EntraID_RoleAssignments_$timestamp.csv"
$roleAssignments | Select-Object @{N='Subscription';E={$subName}}, @{N='SubscriptionId';E={$subId}}, DisplayName, ObjectId, ObjectType, RoleDefinitionName, RoleDefinitionId, Scope |
    Export-Csv -Path $rawRoleCsv -NoTypeInformation -Encoding UTF8
Write-Host "Role assignments CSV exported to: $rawRoleCsv" -ForegroundColor Green
