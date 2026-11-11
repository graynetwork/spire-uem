# SpireUEM Administrator Operations Guide

This guide provides step-by-step instructions for IT administrators and security engineers managing Debian workstation fleets using the SpireUEM control plane (`/admin`).

---

## 1. Initial Access & Authentication

### 1.1. Default Local Credentials
When deploying SpireUEM for the first time via `docker compose`, an initial administrative account is seeded:
- **URL**: `https://<spire-server-host>:18080/admin`
- **Username**: `admin`
- **Password**: `changeme`

> [!IMPORTANT]
> Immediately upon initial login, navigate to **Settings** $\rightarrow$ **Users & Roles** and update the password for the `admin` account, or provision custom administrator accounts and disable default credentials.

### 1.2. Role-Based Access Control (RBAC) Hierarchy
Administrative permissions are strictly partitioned across four roles:

| Role | Scope | Permitted Actions |
| :--- | :--- | :--- |
| **`SUPER_ADMIN`** | Complete Control | Modify global server settings, configure OIDC SSO, manage enrollment tokens, create/deactivate admin users, reveal LUKS recovery keys. |
| **`SECURITY_ADMIN`** | Governance & Baselines | Author declarative policies, upload Flatpak application bundles, trigger fleet CIS benchmark scans, reveal LUKS keys. |
| **`OPERATOR`** | Daily Fleet Operations | Trigger device check-ins, reboot endpoints, dispatch diagnostic commands, initiate interactive PTY terminal and remote assist sessions. |
| **`AUDITOR`** | Compliance & Reporting | View registered endpoints, inspect policy compliance status, and download CSV/JSON compliance audit exports. |

---

## 2. Managing Declarative Policies

Navigate to `/admin/policies` to author and monitor compliance policies.

### 2.1. Kernel Sysctl Baselines (`SYSCTL_SETTING`)
Enforces low-level kernel security parameters atomically written to `/etc/sysctl.d/20-spire-<id>.conf`:
1. Click **New Policy**.
2. Set **Policy Type** to `SYSCTL_SETTING`.
3. Enter key-value pairs (e.g. `net.ipv4.conf.all.rp_filter=1`, `kernel.kptr_restrict=2`).
4. Select target tags (e.g., `workstation`, `kiosk`) or leave empty for global fleet targeting.
5. Click **Create Policy**. Endpoints will apply parameters via `sysctl -w` on next sync.

### 2.2. GNOME Desktop Lockdowns (`DCONF_SETTING`)
Controls desktop behavior and prevents user tampering via dconf database locks:
1. Set **Policy Type** to `DCONF_SETTING`.
2. Define the key path and desired value:
   - Screen Lock Delay: `/org/gnome/desktop/session/idle-delay` $\rightarrow$ `uint32 900` (15 mins).
   - Mandatory Lock: `/org/gnome/desktop/screensaver/lock-enabled` $\rightarrow$ `true`.
   - Notification Privacy: `/org/gnome/desktop/notifications/show-in-lock-screen` $\rightarrow$ `false`.
3. Check **Enforce Mandatory Lock** to prevent desktop users from altering the setting.

### 2.3. Enterprise Desktop Branding & Wallpaper
1. Navigate to `/admin/policies`.
2. Click **Upload Wallpaper Asset** to upload corporate branding (`.png` / `.jpg`).
3. Deploy the pre-built template **"Corporate Desktop Baseline"** from the template selector. This automatically applies the corporate background, GDM login banner, and idle lock parameters.

---

## 3. Application Lifecycle Management

Navigate to `/admin/applications` to manage enterprise software distribution.

### 3.1. Assignment Modes: `REQUIRED` vs `AVAILABLE`
- **`REQUIRED`**: Mandatory corporate software (e.g., VPN clients, EDR sensors, standard browsers). The `spired` daemon enforces installation on every check-in. If removed by a local user, `spired` automatically reinstalls it.
- **`AVAILABLE`**: Optional productivity software published to the **Spire Hub** catalog. End users can install or uninstall these on demand without administrative assistance.

### 3.2. Curated Flathub Distribution
1. Click **Add Application**.
2. Select **Source**: `Flathub`.
3. Specify Application ID (e.g., `org.mozilla.firefox`, `com.visualstudio.code`, `org.videolan.VLC`).
4. Choose **Assignment Type**: `REQUIRED` or `AVAILABLE`.
5. Specify **Target Tags** or assign globally.

### 3.3. Air-Gapped Custom Flatpak Bundles (`.flatpak`)
For proprietary internal applications or air-gapped deployments:
1. Click **Upload Custom Bundle**.
2. Select your pre-built `.flatpak` single-file binary.
3. SpireUEM streams the bundle to `/app/storage/bundles/`, computes its SHA-256 fingerprint, and creates an associated policy.
4. When endpoints synchronize, `spired` downloads the bundle over HTTPS, validates SHA-256 integrity, and installs it via `flatpak install --bundle --system`.

---

## 4. Single Sign-On (OIDC) Integration

Navigate to **Settings** $\rightarrow$ **Single Sign-On (OIDC)** to configure corporate identity federation.

### 4.1. Supported Identity Providers
- **Microsoft Entra ID (Azure AD)**
- **Okta**
- **Keycloak**
- **Google Workspace (Cloud Identity)**

### 4.2. Configuration Parameters
- **Issuer URL**: The base URL of the IdP (e.g., `https://login.microsoftonline.com/<tenant-id>/v2.0` or `https://keycloak.corp/realms/enterprise`).
- **Client ID**: Registered OAuth2 / OIDC Application ID.
- **Client Secret**: Application client secret generated in your IdP console.
- **Scopes**: `openid,profile,email,groups`.
- **Groups Claim Name**: Name of the JWT claim containing group memberships (typically `groups` or `roles`).
- **Allow Local Login**: Toggle whether local username/password login remains available as a fallback.

### 4.3. Configuring Group-to-Role Mappings
In the **IdP Group Mappings** table, create translation rules mapping your IdP security groups to SpireUEM roles:

```text
Entra ID Security Group          SpireUEM Role
-----------------------          -------------
"SecOps-Engineers"          -->  SECURITY_ADMIN
"IT-Service-Desk"           -->  OPERATOR
"Compliance-Auditors"       -->  AUDITOR
"Enterprise-Admins"         -->  SUPER_ADMIN
```
When an administrator logs in via SSO, SpireUEM resolves the highest-privilege matched role and JIT-provisions the user account.

---

## 5. Dynamic Enrollment Tokens

Navigate to **Settings** $\rightarrow$ **Enrollment Tokens** to provision endpoint onboarding tokens.

### 5.1. Token Configuration
1. Click **Generate New Token**.
2. **Target Patch Ring**: Select `ALPHA`, `BETA`, or `GENERAL`. Endpoints using this token will automatically join the designated update ring.
3. **Target Tags**: Enter initial tags (e.g., `finance-fleet`, `kiosk`).
4. **Max Uses**: Define maximum registration count (or 0 for unlimited).
5. **Expiration**: Set token validity window (e.g., 24 hours, 7 days).
6. Click **Generate**. The plaintext token (`spire_tok_...`) is displayed **once**. Store it in your deployment runbook or secret manager.

### 5.2. Token Revocation
To immediately terminate onboarding access for a leaked or expired token, click **Revoke**. All subsequent enrollment requests presenting the revoked token will be rejected with `HTTP 401 Unauthorized`.

---

## 6. Remote Assistance & Diagnostic PTY

### 6.1. Interactive Web PTY Shell
1. Navigate to **Devices** $\rightarrow$ select an endpoint.
2. In the telemetry drawer, click **Open Diagnostic Terminal**.
3. A secure VT100 terminal connects via WebSocket to `spired`, spawning an interactive root shell (`/bin/bash`).
4. All commands are multiplexed and logged with session audit timestamps.

### 6.2. Attended Desktop Remote Assistance
1. In the device detail view, click **Request Remote Assistance**.
2. The control plane dispatches a `REMOTE_ASSIST_REQUEST` WebSocket event to `spired`.
3. `spired` forwards the request across the UNIX domain socket to **Spire Hub** on the user's active desktop session.
4. A prominent authorization dialog appears on the user's screen: *"IT Administrator is requesting remote assistance"*.
5. Only when the local desktop user clicks **Authorize** does the remote screen session establish.

---

## 7. Auditing, SIEM & Compliance Exports

### 7.1. SIEM Syslog Forwarding (RFC 5424)
SpireUEM streams structured JSON audit events over UDP/TLS syslog to your corporate SIEM (Splunk, Elastic, Sentinel):
- Navigate to **Settings** $\rightarrow$ **SIEM Forwarding**.
- Enter your syslog daemon target: `syslog.corp.local:514`.
- Click **Send Test Event** to verify RFC 5424 delivery.

### 7.2. Compliance Audit Exports
Navigate to `/admin/compliance/export` to generate real-time fleet compliance reports:
- **CSV Export**: `GET /admin/compliance/export?format=csv` (suitable for spreadsheets and executive reporting).
- **JSON Export**: `GET /admin/compliance/export?format=json` (suitable for programmatic API ingestion).
