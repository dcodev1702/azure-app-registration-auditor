# MDE Device Isolation Manager

A PowerShell 7 script that dynamically discovers Microsoft Defender for Endpoint (MDE) enrolled devices, displays real-time sensor health and version information, and provides an interactive menu to **isolate** or **unisolate** machines.

![image](https://github.com/user-attachments/assets/4ae7b2ec-848b-40d2-b7b9-944d51e714ee)

---

Audit Trail of Service Principal Auth via KQL

![image](https://github.com/user-attachments/assets/245da5cf-1e3d-4dac-9417-f73772242ba3)


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

Certain devices (e.g., `blueDomainServer`) are configured as exclusions and cannot be isolated through the script. They can still be unisolated if needed.

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

> [!note]
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
| Azure App Registration | https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade |
| Az.Accounts module | https://learn.microsoft.com/en-us/powershell/module/az.accounts |
