#Requires -Version 7
#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Date: 22 Feb 2026
    Authors: DCODEV1702 & Claude Opus 4.6
    
    Manages isolation state for MDE-enrolled devices and displays real-time
    sensor health, version, and OS information.

.DESCRIPTION
    1. Loads app registration credentials from appConfig.json and authenticates
       as a service principal via Azure (Connect-AzAccount).
    2. Checks whether the service principal holds the Global Administrator role.
    3. Acquires a separate MDE API token using OAuth2 client credentials.
    4. Looks up all monitored machines via the MDE REST API, preferring FQDN
       records (*.contoso.range) over short-name entries.
    5. Queries Microsoft Graph Advanced Hunting (KQL) to dynamically discover
       onboarded "blue*" devices and retrieve:
       - MDE sensor version (from DeviceTvmSoftwareInventory)
       - Sensor health state, onboarding status, OS platform, and OS version
         (from DeviceInfo)
       Duplicate device entries are deduplicated by preferring FQDN records
       and Active sensor health over Inactive. Devices reporting sensor
       version 1.0 are excluded from display.
    6. Checks each device's isolation status via the MDE machine actions API
       and displays color-coded results (yellow = isolated, green = not isolated).
    7. Presents an interactive menu allowing the operator to:
       - Isolate a non-isolated device (Full isolation)
       - Unisolate an isolated device
       Certain devices (e.g., blueDomainServer) are excluded from isolation.
       ClientVersionNotSupported errors are handled gracefully.

.NOTES
    Required permissions (WindowsDefenderATP, Application):
      - Machine.Read.All     — list machines and query machine actions
      - Machine.Isolate      — isolate and unisolate machines

    Required permissions (Microsoft Graph, Application):
      - ThreatHunting.Read.All       — Advanced Hunting queries for sensor info
      - RoleManagement.Read.Directory — Global Administrator role check (optional)

    An appConfig.json file must exist alongside this script with the following keys:
      client_id, client_secret, tenant_id, subscription_id

    MDE API rate limits: 100 calls/min, 1500 calls/hr.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Machines that must never be isolated (can still be unisolated if needed)
$isolationExclusions = @(
    'bluedc-01.contoso.local'
)

# ── 1. Load app registration config and authenticate ──────────────────────────

$configPath = Join-Path $PSScriptRoot 'appConfig.json'
if (-not (Test-Path $configPath)) {
    throw "App config file not found: $configPath"
}

$appConfig      = Get-Content $configPath -Raw | ConvertFrom-Json
$tenantId       = $appConfig.tenant_id
$subscriptionId = $appConfig.subscription_id
$clientId       = $appConfig.client_id
$clientSecret   = $appConfig.client_secret

# Connect as the service principal using the app registration credentials
$secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$credential   = [PSCredential]::new($clientId, $secureSecret)

Write-Host "Authenticating as app registration (Client ID: $clientId) ..."
Connect-AzAccount -ServicePrincipal -Credential $credential `
                  -Tenant $tenantId | Out-Null

$azCtx     = Get-AzContext
$accountId = $azCtx.Account.Id

Write-Host "Tenant ID       " -ForegroundColor Green -NoNewline; Write-Host ": $tenantId"
Write-Host "Subscription ID " -ForegroundColor Green -NoNewline; Write-Host ": $subscriptionId"
Write-Host "Client ID       " -ForegroundColor Green -NoNewline; Write-Host ": $clientId"

# ── 1b. Check for active Global Administrator role ────────────────────────────

$spObj     = Get-AzADServicePrincipal -ApplicationId $clientId
$spId      = $spObj.Id
$rolesUri  = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$spId'&`$expand=roleDefinition"
$rolesResp = Invoke-AzRestMethod -Method GET -Uri $rolesUri
$roles     = ($rolesResp.Content | ConvertFrom-Json).value

$gaRole = $roles | Where-Object { $_.roleDefinition.displayName -eq 'Global Administrator' }
if ($gaRole) {
    Write-Host "Global Admin    " -ForegroundColor Yellow -NoNewline; Write-Host ": " -NoNewline; Write-Host "ACTIVE" -ForegroundColor Magenta
} else {
    Write-Host "Global Admin    " -ForegroundColor Yellow -NoNewline; Write-Host ": " -NoNewline; Write-Host "NOT ACTIVE" -ForegroundColor Green -NoNewline; Write-Host " — the app registration may not have GA role assigned."
}

Write-Host ""

# ── 1c. Acquire MDE API token (client credentials) ───────────────────────────

$mdeTokenUri  = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$mdeTokenBody = @{
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = 'https://api.securitycenter.microsoft.com/.default'
    grant_type    = 'client_credentials'
}

Write-Host "Acquiring MDE API token ..."
$mdeTokenResp = Invoke-RestMethod -Method POST -Uri $mdeTokenUri -Body $mdeTokenBody -ContentType 'application/x-www-form-urlencoded'
$mdeHeaders   = @{
    Authorization  = "Bearer $($mdeTokenResp.access_token)"
    'Content-Type' = 'application/json'
}
Write-Host "MDE API token acquired."
Write-Host ""

$mdeApiBase = 'https://api.securitycenter.microsoft.com/api'

# ── 2. Discover enrolled devices and sensor info via Advanced Hunting ────────

$graphHuntUri = 'https://graph.microsoft.com/v1.0/security/runHuntingQuery'

# Dynamically discover onboarded "blue*" devices and get sensor info via
# DeviceTvmSoftwareInventory joined with DeviceInfo.
$sensorQuery = @"
let enrolledDevices = DeviceInfo
| where DeviceName startswith "blue"
| where OnboardingStatus == "Onboarded"
| distinct DeviceName;
let sensorVersions = DeviceTvmSoftwareInventory
| where DeviceName in~ (enrolledDevices)
| where SoftwareName has "sense" or SoftwareName has "defender_for_endpoint"
| summarize SensorVersion = max(SoftwareVersion) by DeviceId, DeviceName;
DeviceInfo
| where DeviceName in~ (enrolledDevices)
| summarize arg_max(Timestamp, DeviceName, ClientVersion, SensorHealthState, OnboardingStatus, OSPlatform, OSVersion) by DeviceId
| project DeviceId, DeviceName, ClientVersion, SensorHealthState, OnboardingStatus, OSPlatform, OSVersion
| join kind=leftouter sensorVersions on DeviceId
| project DeviceName, SensorVersion = coalesce(SensorVersion, ClientVersion), SensorHealthState, OnboardingStatus, OSPlatform, OSVersion
| order by DeviceName asc
"@

Write-Host "Discovering enrolled devices via Advanced Hunting ..."

$sensorBody = @{ Query = $sensorQuery } | ConvertTo-Json
$sensorResp = Invoke-AzRestMethod -Method POST -Uri $graphHuntUri -Payload $sensorBody

# Deduplicate and display sensor info, then extract device names for MDE lookup
$dedupedResults = @()

if ($sensorResp.StatusCode -eq 200) {
    $sensorData = ($sensorResp.Content | ConvertFrom-Json)
    if ($sensorData.results -and $sensorData.results.Count -gt 0) {
        # Deduplicate: prefer FQDN (contoso.range) over short name, then Active over Inactive
        $shortNameKey = { ($_.DeviceName -split '\.')[0].ToLower() }
        $grouped = $sensorData.results | Group-Object -Property $shortNameKey
        $dedupedResults = @(foreach ($g in $grouped) {
            if ($g.Count -gt 1) {
                # Prefer the FQDN entry (contains contoso.range)
                $fqdn = $g.Group | Where-Object { $_.DeviceName -match '\.contoso\.range' }
                $pool = if ($fqdn) { @($fqdn) } else { @($g.Group) }
                # Then prefer Active over Inactive
                $active = $pool | Where-Object { $_.SensorHealthState -eq 'Active' }
                if ($active) { $active | Select-Object -First 1 } else { $pool | Select-Object -First 1 }
            } else {
                $g.Group[0]
            }
        })

        Write-Host ""
        Write-Host "════════════════════════════════════════════════════════════════════════════════════════"
        Write-Host " MDE SENSOR INFORMATION" -ForegroundColor Cyan
        Write-Host "════════════════════════════════════════════════════════════════════════════════════════"
        Write-Host ("{0,-30} {1,-22} {2,-16} {3,-14} {4}" -f "Device", "Sensor Version", "Sensor Health", "Onboarding", "OS")
        Write-Host ("{0,-30} {1,-22} {2,-16} {3,-14} {4}" -f "------", "--------------", "-------------", "----------", "--")
        foreach ($s in $dedupedResults) {
            $sensorVer = if ($s.SensorVersion) { $s.SensorVersion } else { '(unknown)' }
            if ($sensorVer -eq '1.0') { continue }
            $healthColor = if ($s.SensorHealthState -eq 'Active') { 'Green' } else { 'Red' }
            $onboardColor = if ($s.OnboardingStatus -eq 'Onboarded') { 'Cyan' } else { 'Red' }
            Write-Host ("{0,-30} {1,-22} " -f $s.DeviceName, $sensorVer) -NoNewline
            Write-Host ("{0,-16} " -f $s.SensorHealthState) -ForegroundColor $healthColor -NoNewline
            Write-Host ("{0,-14} " -f $s.OnboardingStatus) -ForegroundColor $onboardColor -NoNewline
            Write-Host ("$($s.OSPlatform) $($s.OSVersion)")
        }
        Write-Host "════════════════════════════════════════════════════════════════════════════════════════"
    } else {
        Write-Host "  No enrolled devices found via Advanced Hunting."
    }
} else {
    Write-Host "  WARNING: Could not query enrolled devices (HTTP $($sensorResp.StatusCode)). Continuing without sensor info."
}

Write-Host ""

# Build device name list from KQL results (excluding sensor version 1.0)
$discoveredNames = @($dedupedResults |
    Where-Object { $_.SensorVersion -ne '1.0' -and $_.SensorVersion } |
    ForEach-Object { $_.DeviceName })

if ($discoveredNames.Count -eq 0) {
    throw "No active enrolled devices discovered. Verify devices are onboarded to MDE."
}

# ── 3. Look up discovered machines via MDE API ───────────────────────────────

Write-Host "Looking up $($discoveredNames.Count) discovered device(s) via MDE API ..."

$devices = @()
foreach ($name in $discoveredNames) {
    $machineUri  = "$mdeApiBase/machines?`$filter=computerDnsName+eq+'$name'"
    $machineResp = Invoke-RestMethod -Method GET -Uri $machineUri -Headers $mdeHeaders

    if ($machineResp.value -and $machineResp.value.Count -gt 0) {
        $best = $machineResp.value |
                Sort-Object -Property lastSeen -Descending |
                Select-Object -First 1
        $devices += $best
    } else {
        Write-Host "  SKIP: '$name' not found via MDE API."
    }
}

if ($devices.Count -eq 0) {
    throw "No MDE machines found for discovered devices."
}

Write-Host "Found $($devices.Count) MDE device(s)."
Write-Host ""

# ── 4. Check isolation status for all devices ────────────────────────────────

Write-Host "Checking isolation status for each device ..."
Write-Host ""

$isolatedDevices    = @()
$notIsolatedDevices = @()

foreach ($device in $devices) {
    $devId      = $device.id
    $devName    = $device.computerDnsName

    # Query the most recent isolate/unisolate action for this machine
    $actionsUri  = "$mdeApiBase/machineactions?`$filter=machineId+eq+'$devId'" +
                   "+and+(type+eq+'Isolate'+or+type+eq+'Unisolate')" +
                   "&`$orderby=creationDateTimeUtc+desc&`$top=1"
    $actionsResp = Invoke-RestMethod -Method GET -Uri $actionsUri -Headers $mdeHeaders

    if ($actionsResp.value -and $actionsResp.value.Count -gt 0) {
        $lastAction = $actionsResp.value[0]
        if ($lastAction.type -eq 'Isolate' -and $lastAction.status -in @('Succeeded', 'Pending', 'InProgress')) {
            Write-Host "  " -NoNewline; Write-Host "[ISOLATED]" -ForegroundColor Yellow -NoNewline; Write-Host "     $devName  ($($lastAction.status) since $($lastAction.creationDateTimeUtc))"
            $isolatedDevices += [PSCustomObject]@{
                DeviceName = $devName
                DeviceId   = $devId
                IsolatedAt = $lastAction.creationDateTimeUtc
            }
        } else {
            Write-Host "  " -NoNewline; Write-Host "[Not isolated]" -ForegroundColor Green -NoNewline; Write-Host " $devName"
            $notIsolatedDevices += [PSCustomObject]@{
                DeviceName = $devName
                DeviceId   = $devId
            }
        }
    } else {
        Write-Host "  " -NoNewline; Write-Host "[Not isolated]" -ForegroundColor Green -NoNewline; Write-Host " $devName  (no isolation history)"
        $notIsolatedDevices += [PSCustomObject]@{
            DeviceName = $devName
            DeviceId   = $devId
        }
    }
}

Write-Host ""

# ── 5. Prompt user to choose an action ───────────────────────────────────────

Write-Host "═══════════════════════════════════════════════════"
Write-Host " ACTIONS"
Write-Host "═══════════════════════════════════════════════════"
Write-Host "  [1] Unisolate a device"
Write-Host "  [2] Isolate a device"
Write-Host "  [0] Exit"
Write-Host "═══════════════════════════════════════════════════"
Write-Host ""

$action = Read-Host "Select an action"

switch ($action) {

    # ── Unisolate ─────────────────────────────────────────────────────────────
    '1' {
        if ($isolatedDevices.Count -eq 0) {
            Write-Host "No machines are currently isolated. Nothing to unisolate."
            return
        }

        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════"
        Write-Host " ISOLATED MACHINES (available to unisolate)"
        Write-Host "═══════════════════════════════════════════════════"
        for ($i = 0; $i -lt $isolatedDevices.Count; $i++) {
            Write-Host "  [$($i + 1)] $($isolatedDevices[$i].DeviceName)  (isolated since $($isolatedDevices[$i].IsolatedAt))"
        }
        Write-Host "  [0] Cancel"
        Write-Host "═══════════════════════════════════════════════════"
        Write-Host ""

        $selection = Read-Host "Enter the number of the machine to unisolate"

        if ($selection -eq '0' -or [string]::IsNullOrWhiteSpace($selection)) {
            Write-Host "Operation cancelled. Exiting."
            return
        }

        $index = [int]$selection - 1
        if ($index -lt 0 -or $index -ge $isolatedDevices.Count) {
            Write-Host "Invalid selection. Exiting."
            return
        }

        $target     = $isolatedDevices[$index]
        $targetName = $target.DeviceName
        $targetId   = $target.DeviceId

        Write-Host ""
        Write-Host "You selected: $targetName ($targetId)"
        Write-Host ""

        # ── 6a. Unisolate the selected machine via MDE API ───────────────────

        $unisolateUri  = "https://api.securitycenter.microsoft.com/api/machines/$targetId/unisolate"
        $unisolateBody = @{
            Comment = "Unisolating $targetName via automated PowerShell script. " +
                      "Initiated by $accountId on $(Get-Date -Format 'u')."
        } | ConvertTo-Json

        Write-Host "Sending unisolate request for '$targetName' ..."
        $actionResult = Invoke-RestMethod -Method POST -Uri $unisolateUri -Headers $mdeHeaders -Body $unisolateBody

        Write-Host ""
        Write-Host "Unisolate action submitted successfully."
        Write-Host "Action ID     : $($actionResult.id)"
        Write-Host "Status        : $($actionResult.status)"
        Write-Host "Created at    : $($actionResult.creationDateTimeUtc)"
        Write-Host "Requestor     : $($actionResult.requestor)"
        Write-Host ""
        Write-Host "Monitor progress in the Microsoft 365 Defender portal or poll:"
        Write-Host "  GET https://api.securitycenter.microsoft.com/api/machineactions/$($actionResult.id)"
    }

    # ── Isolate ───────────────────────────────────────────────────────────────
    '2' {
        # Filter out machines that must never be isolated
        $isolateCandidates = $notIsolatedDevices | Where-Object {
            $_.DeviceName -notin $isolationExclusions
        }

        if ($isolateCandidates.Count -eq 0) {
            Write-Host "No machines are available to isolate. Nothing to do."
            return
        }

        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════"
        Write-Host " NON-ISOLATED MACHINES (available to isolate)"
        Write-Host "═══════════════════════════════════════════════════"
        for ($i = 0; $i -lt $isolateCandidates.Count; $i++) {
            Write-Host "  [$($i + 1)] $($isolateCandidates[$i].DeviceName)"
        }
        Write-Host "  [0] Cancel"
        Write-Host "═══════════════════════════════════════════════════"
        Write-Host ""

        $selection = Read-Host "Enter the number of the machine to isolate"

        if ($selection -eq '0' -or [string]::IsNullOrWhiteSpace($selection)) {
            Write-Host "Operation cancelled. Exiting."
            return
        }

        $index = [int]$selection - 1
        if ($index -lt 0 -or $index -ge $isolateCandidates.Count) {
            Write-Host "Invalid selection. Exiting."
            return
        }

        $target     = $isolateCandidates[$index]
        $targetName = $target.DeviceName
        $targetId   = $target.DeviceId

        Write-Host ""
        Write-Host "You selected: $targetName ($targetId)"
        Write-Host ""

        # ── 6b. Isolate the selected machine via MDE API ─────────────────────

        $isolateUri  = "https://api.securitycenter.microsoft.com/api/machines/$targetId/isolate"
        $isolateBody = @{
            Comment       = "Isolating $targetName via automated PowerShell script. " +
                            "Initiated by $accountId on $(Get-Date -Format 'u')."
            IsolationType = 'Full'
        } | ConvertTo-Json

        Write-Host "Sending isolate request for '$targetName' ..."
        try {
            $actionResult = Invoke-RestMethod -Method POST -Uri $isolateUri -Headers $mdeHeaders -Body $isolateBody
        } catch {
            $errMsg = ''
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $errMsg = $_.ErrorDetails.Message
            } elseif ($_.Exception.Response) {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $errMsg = $reader.ReadToEnd()
                $reader.Close()
            }
            if ($errMsg -match 'ClientVersionNotSupported') {
                Write-Host ""
                Write-Host "ERROR: '$targetName' cannot be isolated — its MDE sensor version is too old."
                Write-Host "       Update the MDE sensor on this device and try again."
                return
            }
            throw
        }

        Write-Host ""
        Write-Host "Isolate action submitted successfully."
        Write-Host "Action ID     : $($actionResult.id)"
        Write-Host "Status        : $($actionResult.status)"
        Write-Host "Created at    : $($actionResult.creationDateTimeUtc)"
        Write-Host "Requestor     : $($actionResult.requestor)"
        Write-Host ""
        Write-Host "Monitor progress in the Microsoft 365 Defender portal or poll:"
        Write-Host "  GET https://api.securitycenter.microsoft.com/api/machineactions/$($actionResult.id)"
    }

    # ── Exit ──────────────────────────────────────────────────────────────────
    '0' {
        Write-Host "Exiting."
        return
    }

    default {
        Write-Host "Invalid selection. Exiting."
        return
    }
}
