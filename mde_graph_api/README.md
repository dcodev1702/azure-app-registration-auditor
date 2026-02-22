# MDE Device Isolation Manager

A PowerShell 7 script that dynamically discovers Microsoft Defender for Endpoint (MDE) enrolled devices, displays real-time sensor health and version information, and provides an interactive menu to **isolate** or **unisolate** machines.

![image](https://github.com/user-attachments/assets/4ae7b2ec-848b-40d2-b7b9-944d51e714ee)

Graph & WindowsDefenderATP API (Application Registration: Azure PowerShell) actions verified via the Defender XDR portal

![image](https://github.com/user-attachments/assets/0eacc592-d3c4-4546-ad05-710649525cc7)

---


## What It Does

1. **Authenticates** as a service principal using credentials from `appConfig.json` via `Connect-AzAccount`.
2. **Checks Global Administrator role** status for the service principal via Microsoft Graph.
3. **Acquires an MDE API token** using OAuth2 client credentials flow.
4. **Discovers enrolled devices** dynamically via [Advanced Hunting](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview) KQL queries — no hardcoded device list required. Devices are discovered by matching `DeviceName startswith "blue"` with `OnboardingStatus == "Onboarded"`.
5. **Displays a color-coded sensor information table** showing:
   - Device name (FQDN)
   - MDE sensor version (sourced from [`DeviceTvmSoftwareInventory`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwareinventory-table), with [`DeviceInfo.ClientVersion`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) as fallback)
   - Sensor health state (**Active** = green, **Inactive** = red)
   - Onboarding status (**Onboarded** = cyan, other = red)
   - OS platform and version
6. **Checks isolation status** for each device via the MDE [machine actions API](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machineaction-object) and displays results (**Isolated** = yellow, **Not isolated** = green).
7. **Interactive action menu** to isolate or unisolate a selected device via the MDE [isolate](https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine) / [unisolate](https://learn.microsoft.com/en-us/defender-endpoint/api/unisolate-machine) APIs.

### Deduplication Logic

- If a device appears with both an FQDN (e.g., `bluews-01.contoso.range`) and a short name, the FQDN record is preferred.
- If a device appears with both **Active** and **Inactive** sensor health, the **Active** record is kept.
- Devices reporting sensor version `1.0` are excluded from display.

### Isolation Exclusions

Certain devices are configured as exclusions and **cannot be isolated** through the script. They can still be unisolated if needed.

The exclusion list is defined at the top of `mde_device_actions.ps1`:

```powershell
$isolationExclusions = @(
    'bluedc-01.contoso.range'
)
```

**How it works:**
- When the user selects **Isolate a device** from the action menu, the script filters out any device whose `DeviceName` matches an entry in `$isolationExclusions`.
- Excluded devices are silently removed from the isolation candidate list — they simply don't appear as options.
- This is a **one-way protection**: excluded devices can still be **unisolated** if they were previously isolated through another method (e.g., the Defender portal or a different script).
- To add or remove exclusions, edit the `$isolationExclusions` array. Use the full FQDN (e.g., `bluedc-01.contoso.range`) to match exactly.

> [!IMPORTANT]
> Exclusions are enforced **only within this script**. They do not prevent isolation via the Defender portal, Microsoft Graph API, or other automation tools. This is a safety guard for domain controllers and critical infrastructure servers that should never be network-isolated during an investigation.

---

## Requirements

### PowerShell

- **PowerShell 7+** (`#Requires -Version 7`)
- **Az.Accounts module** (`#Requires -Modules Az.Accounts`)

Install the module if needed:

```powershell
Install-Module Az.Accounts -Scope CurrentUser
```

### App Registration (Azure Entra ID)

An app registration is required with the following API permissions granted and admin-consented:

| API | Permission | Type | Purpose |
|-----|-----------|------|---------|
| **WindowsDefenderATP** | `Machine.Read.All` | Application | List machines, query machine actions |
| **WindowsDefenderATP** | `Machine.Isolate` | Application | Isolate and unisolate machines |
| **Microsoft Graph** | `ThreatHunting.Read.All` | Application | Advanced Hunting queries for sensor info |
| **Microsoft Graph** | `RoleManagement.Read.Directory` | Application | Global Administrator role check (optional) |

Configure permissions in the [Azure Portal — App Registrations](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade).

> [!TIP]
> Use `Invoke-MDEAppRegistrationSetup.ps1` (included in this directory) to create the app registration, assign all permissions, grant admin consent, and generate `appConfig.json` automatically — no portal GUI click-ops required!

### Automated App Registration Setup

`Invoke-MDEAppRegistrationSetup.ps1` provisions everything programmatically:

1. Creates an app registration (`mde_device_manager`) in Entra ID
2. Creates a service principal for the app
3. Assigns **Application** permissions to both APIs:
   - **WindowsDefenderATP** — `Machine.Read.All`, `Machine.Isolate`
   - **Microsoft Graph** — `ThreatHunting.Read.All`, `RoleManagement.Read.Directory`
4. Grants **admin consent** for all four permissions
5. Creates a client secret (36-month validity) with a named description
6. Writes `appConfig.json` with `client_id`, `client_secret`, `tenant_id`, and `subscription_id`

```powershell
# Run from the mde_graph_api directory
./Invoke-MDEAppRegistrationSetup.ps1
```

The script requires an active `Connect-AzAccount` session with permissions to create app registrations and grant admin consent (typically Global Administrator or Application Administrator).

### `appConfig.json`

Create an `appConfig.json` file in the same directory as the script with your app registration credentials:

```json
{
    "client_id": "your-client-id-guid",
    "client_secret": "your-client-secret-value",
    "tenant_id": "your-tenant-id-guid",
    "subscription_id": "your-subscription-id-guid"
}
```

> [!NOTE]
> Do not commit `appConfig.json` to source control. Add it to your `.gitignore`.

---

## Usage

```powershell
./mde_device_actions.ps1
```

The script will authenticate, discover devices, display sensor information, check isolation status, and present an action menu:

```
═══════════════════════════════════════════════════
 ACTIONS
═══════════════════════════════════════════════════
  [1] Unisolate a device
  [2] Isolate a device
  [0] Exit
═══════════════════════════════════════════════════
```

---

## API Rate Limits

MDE API enforces rate limits of **100 calls/minute** and **1,500 calls/hour**. The script makes one API call per device for lookup and isolation status checks.

---

## 🔍 Forensic Correlation — KQL Queries

The service principal's activity across Microsoft Graph, MDE API, and Azure Resource Manager is fully auditable via KQL. The following queries correlate `AADServicePrincipalSignInLogs` with downstream service logs to build a complete forensic timeline.

### Correlating Graph API Activity

Every Microsoft Graph call made by the service principal (e.g., advanced hunting queries, directory role checks) is captured in `MicrosoftGraphActivityLogs`. Join on the token identifier to see the exact Graph endpoint called:

```kusto
// Graph API calls made by the service principal
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| where AppId == "<your-app-id>"
| where ResourceDisplayName == "Microsoft Graph"
| join kind=inner (
    MicrosoftGraphActivityLogs
    | where TimeGenerated > ago(7d)
) on $left.UniqueTokenIdentifier == $right.SignInActivityId
| project TimeGenerated, ServicePrincipalName, ClientCredentialType,
          RequestMethod, RequestUri, ResponseStatusCode, IPAddress
```

**What you'll see:** Each row shows the exact Graph REST endpoint the SP called — for example `POST /security/runHuntingQuery` (advanced hunting), `GET /roleManagement/directory/roleAssignments` (GA role check), or `GET /servicePrincipals` (SP lookup).

![Graph API Activity](https://github.com/user-attachments/assets/245da5cf-1e3d-4dac-9417-f73772242ba3)

### Correlating MDE / Defender XDR Activity

MDE API calls (device isolation, machine listing) are captured in `CloudAppEvents` when app governance is enabled. Join on the service principal's object ID:

```kusto
// MDE API actions correlated with SP sign-ins
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| where AppId == "<your-app-id>"
| join kind=inner (
    CloudAppEvents
    | where TimeGenerated > ago(7d)
) on $left.AppId == $right.ObjectId
```

**What you'll see:** Actions like device isolation/unisolation, machine queries, and any Defender XDR operations performed by the service principal — correlated with the sign-in event that authorized them.

### Full Cross-Service Timeline

Combine all sources into a unified timeline showing every action the service principal took across all Azure and M365 services:

| SP Signs Into | `ResourceDisplayName` | Correlate With | Join Key |
|---|---|---|---|
| Graph API | `Microsoft Graph` | `MicrosoftGraphActivityLogs` | `UniqueTokenIdentifier` = `SignInActivityId` |
| ARM | `Windows Azure Service Management API` | `AzureActivity` | `AppId` = `Caller` |
| MDE API | `Windows Defender ATP` | `CloudAppEvents` | `AppId` = `ObjectId` |
| Storage | `Azure Storage` | `StorageBlobLogs` | `AppId` = `RequesterAppId` |
| Entra ID changes | N/A (directory ops) | `AuditLogs` | `AppId` = `InitiatedBy.app.appId` |

> [!TIP]
> The `ClientCredentialType` column in `AADServicePrincipalSignInLogs` distinguishes `Certificate` vs `ClientSecret` for **every** service call — not just storage. If an attacker steals a secret and uses it to isolate a device, the sign-in log shows exactly which credential was used, from which IP, and at what time.

---

## Reference Links

| Resource | URL |
|----------|-----|
| DeviceInfo table schema | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table |
| DeviceTvmSoftwareInventory table schema | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwareinventory-table |
| Advanced Hunting overview | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview |
| MDE Isolate machine API | https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine |
| MDE Unisolate machine API | https://learn.microsoft.com/en-us/defender-endpoint/api/unisolate-machine |
| MDE Machine actions API | https://learn.microsoft.com/en-us/defender-endpoint/api/get-machineaction-object |
| MDE List machines API | https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines |
| Graph Advanced Hunting API | https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery |
| MicrosoftGraphActivityLogs | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs |
| AADServicePrincipalSignInLogs | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs |
| CloudAppEvents | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table |
| Azure App Registration | https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade |
| Az.Accounts module | https://learn.microsoft.com/en-us/powershell/module/az.accounts |
