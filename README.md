# Azure App Registration & Entra ID Auditor

A collection of PowerShell scripts for auditing Azure App Registrations, Entra ID users, and RBAC role assignments. Designed for security professionals, cloud administrators, and incident responders who need quick visibility into their Azure tenant's identity and access posture.

## Scripts

### `Get-AzAppRegistrationAudit.ps1`

Enumerates all Azure AD app registrations and reports:

- **RBAC Role Assignments** — which roles each app's service principal holds and at what scope
- **API Permissions** — application and delegated permissions resolved to human-readable names (e.g., `Mail.Read` instead of a GUID)
- **Credentials** — client secrets (with hint/first characters) and certificates (with thumbprint), including expiration status (`Active`, `EXPIRING SOON`, `EXPIRED`)

Configurable exclusion patterns allow you to skip known/benign app registrations.

### `Get-EntraIDUser2AzureRoleAudit.ps1`

Maps all Entra ID users to their Azure RBAC role assignments and enriches the output with:

- **Entra ID Directory Roles** — identifies Global Administrators and User Administrators via Graph API
- **Subscription-Level Contributors** — flags users with Contributor access at the subscription scope
- **Complete user-to-role correlation** — every user is listed, even those with no role assignments

## Prerequisites

### Required Modules

| Module | Minimum Version | Purpose |
|--------|----------------|---------|
| `Az.Accounts` | 2.12.0+ | Authentication (`Connect-AzAccount`) |
| `Az.Resources` | 6.0.0+ | `Get-AzADApplication`, `Get-AzRoleAssignment`, `Get-AzADUser`, etc. |

### Installation

```powershell
# Install from PowerShell Gallery
Install-Module -Name Az.Accounts -Scope CurrentUser -Force
Install-Module -Name Az.Resources -Scope CurrentUser -Force
```

### Authentication

You must be authenticated to Azure before running either script:

```powershell
# Interactive login
Connect-AzAccount

# Or with a specific tenant
Connect-AzAccount -TenantId "your-tenant-id"
```

> **Note:** `Invoke-AzRestMethod` is used internally to call the Microsoft Graph API for directory role lookups. This works transparently through your existing `Connect-AzAccount` session — no separate `Connect-MgGraph` or Microsoft Graph SDK modules are required.

### Required Permissions

| Permission | Source | Used By |
|-----------|--------|---------|
| `Directory.Read.All` | Microsoft Graph (via Az session) | Directory role member lookups |
| `Reader` (or higher) | Azure RBAC | Role assignment enumeration |
| `Application.Read.All` | Azure AD | App registration and credential enumeration |

## Running the Scripts

### Azure Cloud Shell

Azure Cloud Shell (PowerShell) comes with the Az modules pre-installed and pre-authenticated:

```powershell
# Clone the repo
git clone https://github.com/DCODEV1702/azure-app-registration-auditor.git
cd azure-app-registration-auditor

# Run either script directly — no Connect-AzAccount needed in Cloud Shell
./Get-AzAppRegistrationAudit.ps1
./Get-EntraIDUser2AzureRoleAudit.ps1
```

### PowerShell 7 (Local / CLI)

```powershell
# Ensure Az modules are installed
Install-Module -Name Az -Scope CurrentUser -Force

# Authenticate
Connect-AzAccount

# Run
./Get-AzAppRegistrationAudit.ps1
./Get-EntraIDUser2AzureRoleAudit.ps1
```

### Subscription Selection

Both scripts support interactive subscription selection:

- **Single subscription** — automatically selected, no prompt
- **Multiple subscriptions** — an arrow-key menu is displayed for you to choose

## Output

### Console Output

Both scripts print results directly to the terminal with color-coded sections:

**`Get-AzAppRegistrationAudit.ps1`** displays three tables:
- `=== ROLE ASSIGNMENTS ===` — App name, App ID, service principal, role, and scope
- `=== API PERMISSIONS ===` — App name, resource, permission name, and type (Application/Delegated)
- `=== CREDENTIALS (Secrets & Certificates) ===` — App name, credential type, description, secret hint, thumbprint, dates, and status

**`Get-EntraIDUser2AzureRoleAudit.ps1`** displays:
- **Global Administrators** and **User Administrators** with names and UPNs
- **Subscription-Level Contributors** with display names
- A **user-to-role mapping table** with subscription, display name, UPN, Entra directory roles, contributor flag, RBAC role, and scope

### CSV Export

**`Get-EntraIDUser2AzureRoleAudit.ps1`** automatically exports two timestamped CSV files to the script directory:

| File | Contents |
|------|----------|
| `EntraID_User_Role_Audit_<timestamp>.csv` | Full user-to-role mapping with Subscription, DisplayName, UPN, EntraDirectoryRole, SubLevelContributor, RoleName, and Scope |
| `EntraID_RoleAssignments_<timestamp>.csv` | Raw role assignments with Subscription, DisplayName, ObjectId, ObjectType, RoleDefinitionName, and Scope |

## Configuration

### Excluding App Registrations

In `Get-AzAppRegistrationAudit.ps1`, modify the `$excludeApps` array to skip known apps:

```powershell
$excludeApps = @(
    "^ConnectSyncProvisioning",
    "^GraphEmulationTool"
)
```

Patterns use PowerShell regex (e.g., `^` matches the start of the display name).

## Authors

- **DCODEV1702**
- **Claude Opus 4.6**

## License

MIT
