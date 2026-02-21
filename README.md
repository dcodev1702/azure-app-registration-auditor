# Azure App Registration & Entra ID Auditor

A collection of PowerShell scripts for auditing Azure App Registrations, Entra ID users, and RBAC role assignments. Designed for security professionals, cloud administrators, and incident responders who need quick visibility into their Azure tenant's identity and access posture.

## PowerShell Scripts

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

![IMAGE](https://github.com/user-attachments/assets/57a0d03d-f390-454d-bbe3-ed03a1dcdc57)


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

---

## 🏆 Digital Forensics / Incident Response (DFIR) PoC — `New-DemoDfirAppSetup.ps1`

This script creates a fully functional proof-of-concept environment that demonstrates how app registrations use secrets and certificates to authenticate, and why auditing them matters from a DFIR perspective.

### What It Creates

`New-DemoDfirAppSetup.ps1` provisions the following resources end-to-end:

1. **Self-signed certificate** (RSA 2048-bit, SHA-256, 36-month validity)
   - Exported as a `.pfx` file (private + public key) and a `.cer` file (public key only)
   - Imported into the Windows certificate store at `Cert:\CurrentUser\My`
2. **App registration** (`demo_dfir_app`) in Entra ID with:
   - A **client secret** (36-month validity) — the secret value is shown once at creation and cannot be retrieved again
   - A **certificate credential** — the public key (`.cer`) is uploaded to the app registration
3. **Service principal** for the app registration
4. **Storage account** (`demodfirsa007`) configured for Entra ID-only authentication:
   - Shared key access: **disabled**
   - Anonymous/public blob access: **disabled**
   - Minimum TLS: **1.2**
5. **RBAC role assignment** — `Storage Blob Data Contributor` scoped to the storage account
6. **Blob container** (`demo-dfir-container`) with private access

### Understanding the PFX File

The script generates a [PFX (PKCS #12)](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/personal-information-exchange---pfx--files) file, which is a binary archive containing both the **private key** and the **public certificate** in a single encrypted bundle.

- The `.pfx` is protected with a password (`#Dem0.Df!r_2026!`) — this password is required to import the PFX or extract the private key
- The `.cer` contains only the **public key** and is what gets uploaded to the app registration in Entra ID
- When you import the PFX into the Windows certificate store (`Cert:\CurrentUser\My`), the private key becomes available to the OS for signing authentication tokens

You can view installed certificates in the Windows certificate store via:
```powershell
# PowerShell
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*DemoDfirCert*" }

# GUI: Win+R → certmgr.msc → Personal → Certificates
```

### Delegated vs. Application Permissions

Entra ID supports two permission models for app registrations:

| Type | Who Acts | Requires User Session | Use Case |
|------|----------|----------------------|----------|
| **Delegated** | App acts **on behalf of** a signed-in user | Yes | Interactive apps, web apps with user sign-in |
| **Application** | App acts **as itself** (service principal) | No | Background services, daemons, automation scripts |

`demo_dfir_app` is configured with **Application** permissions — it authenticates as a service principal with no user context. The following Microsoft Graph API permissions are assigned:

| API / Resource | Permission | Type |
|---------------|------------|------|
| Microsoft Graph | `User.Read.All` | Application |

The storage account access is controlled via Azure RBAC (`Storage Blob Data Contributor`), not Graph API permissions — this is the recommended pattern for Azure resource access.

### Authenticating with the App Registration

#### Option A: Certificate-Based Authentication

Certificate auth requires the PFX to be installed in the certificate store of the machine you're running from. The Az module reads the private key locally to sign a JWT, which Entra ID validates against the uploaded public key.

```powershell
Connect-AzAccount `
    -ServicePrincipal `
    -ApplicationId '<client-id>' `
    -TenantId '<tenant-id>' `
    -CertificateThumbprint '<thumbprint>'
```

> [!IMPORTANT]
> You must be on the machine where the PFX was imported. The private key never leaves the local certificate store — Entra ID only has the public key.

#### Option B: Client Secret Authentication

Secret auth works from any machine — you just need the secret value string.

```powershell
$secureSecret = ConvertTo-SecureString '<secret-value>' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential('<client-id>', $secureSecret)
Connect-AzAccount `
    -ServicePrincipal `
    -Credential $credential `
    -TenantId '<tenant-id>'
```

#### Accessing the Storage Account (After Auth)

```powershell
$ctx = New-AzStorageContext -StorageAccountName 'demodfirsa007' -UseConnectedAccount
Get-AzStorageBlob -Container 'demo-dfir-container' -Context $ctx
```

### Forensic Correlation with KQL

The real power of this demo is correlating **how** the app authenticated with **what** it accessed. Two log sources make this possible:

| Log Source | What It Contains |
|-----------|-----------------|
| `AADServicePrincipalSignInLogs` | Entra ID sign-in events for 3rd-party/customer-created service principals, including `ClientCredentialType` (`Certificate` or `ClientSecret`), `ServicePrincipalCredentialKeyId`, and `ServicePrincipalCredentialThumbprint` |
| `StorageBlobLogs` | Every storage operation, including `AuthenticationHash` (a SHA-256 fingerprint of the token signing key), `RequesterAppId`, and `CallerIpAddress` |

Each credential type (secret vs. certificate) produces a **different `AuthenticationHash`** in `StorageBlobLogs`. By joining with `AADServicePrincipalSignInLogs`, you can determine exactly which credential was used for every storage operation.

```kusto
// Join service principal sign-ins with storage blob access logs
// Determines WHICH credential (cert vs secret) was used for each storage operation
let spSignIns = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(7d)
    | where AppId == "<your-app-id>"
    | project
        SignInTime = TimeGenerated,
        AppId,
        ServicePrincipalName,
        ClientCredentialType,
        CredentialKeyId = ServicePrincipalCredentialKeyId,
        CertThumbprint = ServicePrincipalCredentialThumbprint,
        IPAddress,
        ResourceDisplayName;
let storageOps = StorageBlobLogs
    | where TimeGenerated > ago(7d)
    | where AccountName == "demodfirsa007"
    | where AuthenticationType == "OAuth"
    | project
        StorageTime = TimeGenerated,
        AccountName,
        OperationName,
        AuthenticationHash,
        RequesterAppId,
        CallerIpAddress,
        Uri,
        StatusCode;
storageOps
| join kind=inner (spSignIns) on $left.RequesterAppId == $right.AppId
| where abs(datetime_diff('second', StorageTime, SignInTime)) < 120
| project
    StorageTime,
    SignInTime,
    AccountName,
    OperationName,
    StatusCode,
    ClientCredentialType,
    CredentialKeyId,
    CertThumbprint,
    AuthenticationHash,
    CallerIpAddress,
    IPAddress,
    ServicePrincipalName,
    Uri
| order by StorageTime asc
```

**Why this matters for DFIR:** If an attacker compromises a client secret or exports a certificate private key, this join tells you:
- **Which credential** was used (cert or secret, by KeyId)
- **From where** (IP address correlation)
- **What was accessed** (blob URIs, operations)
- **When** (exact timeline)

This is the forensic chain from credential to data exfiltration.

### Tying It Back to the Auditor

After running `New-DemoDfirAppSetup.ps1`, execute `Get-AzAppRegistrationAudit.ps1` to see the demo app in action:

- **Role Assignments** — shows `demo_dfir_app` with `Storage Blob Data Contributor` scoped to the storage account
- **API Permissions** — shows the Microsoft Graph `User.Read.All` application permission
- **Credentials** — shows **both** the client secret (with hint) **and** the certificate (with thumbprint and expiration)

This demonstrates exactly why `Get-AzAppRegistrationAudit.ps1` is valuable: in a real environment with dozens or hundreds of app registrations, it gives you immediate visibility into which apps have credentials, when they expire, what roles they hold, and what APIs they can call — information that is critical for incident response, credential rotation planning, and security posture assessment.

---

## Authors

- **DCODEV1702**
- **Claude Opus 4.6**

## License

MIT
