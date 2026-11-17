# SpireUEM Administrator Guide

This guide describes day-to-day administration of a deployed SpireUEM control plane. For installation, TLS, backup, migration, and recovery procedures, use the [production operations runbook](ADMIN_RUNBOOK.md).

## 1. Access and authentication

Use the public HTTPS URL configured under **Settings → General → server base URL**, for example `https://spire.example.com/admin`.

Port `18080` and plain HTTP belong only to `docker-compose.test.yml`. The root `docker-compose.yml` starts PostgreSQL, not a production control plane.

### 1.1 Initial local access

`SPIRE_ADMIN_PASSWORD` enables a static break-glass account named by `SPIRE_ADMIN_USER` (default `admin`). The password must contain at least 12 characters and must not be a known default. If it is unset, the static account is disabled.

On first start, a configured `SPIRE_ADMIN_PASSWORD` also replaces the seeded `changeme` password of the database-backed `admin` account. The server refuses to start while an active local account still uses `changeme`.

Create named database-backed administrators, configure MFA, and reserve the static account for recovery. The static account has no database row and therefore cannot own personal access tokens or enroll TOTP.

### 1.2 Roles and device scope

| Role | Permissions |
|---|---|
| `SUPER_ADMIN` | Global settings, OIDC, users, enrollment tokens, alert channels, agent rollout, wipe request/approval, and every lower-role action. |
| `SECURITY_ADMIN` | Policy and application management, fleet scans, CVE imports, approval/revocation, tags/rings, lost mode, and LUKS recovery-key reveal. |
| `OPERATOR` | Device sync, reboot, patch, scan, lock, queued root commands, root PTY, and remote-assistance requests. |
| `AUDITOR` | Read-only device, policy, vulnerability, audit, and export access. |

`OPERATOR` and `SECURITY_ADMIN` can be limited to devices carrying specified tags. Their device lists, dashboard totals, vulnerability counts, audit events, and device-targeted actions are filtered server-side. An empty allowed-tag list is unrestricted. `SUPER_ADMIN` and `AUDITOR` are not tag-scoped.

`OPERATOR` can execute commands and open a root PTY on every device within their scope. Grant that role only to administrators trusted with root access to those endpoints.

### 1.3 MFA and personal access tokens

Local database-backed accounts can enroll RFC 6238 TOTP under **Account Security**. Ten single-use recovery codes are shown once. A `SUPER_ADMIN` can require MFA and reset another user's enrollment.

Personal access tokens:

- start with `spire_pat_` and are shown once;
- require an expiry of at most 365 days;
- have a role no higher than their owner;
- are evaluated on every request against the owner's current role and active status;
- use `Authorization: Bearer <token>` and do not require browser CSRF tokens.

## 2. Devices and enrollment

### 2.1 Standard agent flow

The current `spired` bootstrap uses administrator approval:

1. The agent creates `/etc/spire/enrollment.key` and stages the hardware UUID as `PENDING_APPROVAL`.
2. A `SECURITY_ADMIN` or `SUPER_ADMIN` assigns tags/ring and approves the device.
3. The server releases a single-use bearer token only to the agent presenting the bound enrollment key.
4. The agent stores the token at `/etc/spire/token` and begins authenticated check-ins.

After an OS reinstall or deletion of `/etc/spire`, revoke the old device record before enrolling the replacement. Revocation releases the enrollment-key binding.

### 2.2 Dynamic enrollment tokens

**Settings → Enrollment Tokens** creates `spire_tok_...` tokens for provisioning clients that call `POST /api/v1/enrollment/register`. Configure a description, target tags, maximum uses, expiry, and deployment ring.

Supported token ring values are `CANARY`, `BETA`, `PILOT`, and `PRODUCTION`. The standard bootstrap does not accept `--token`, and `spired` does not currently call token registration itself.

Revoked, expired, exhausted, or unknown tokens receive `401 Unauthorized`.

## 3. Declarative policy

Create policy under **Policies**. Policies can target tags, a deployment ring, or the full fleet.

| Type | Managed state |
|---|---|
| `PACKAGE_PRESENCE` / `PACKAGE_ABSENCE` | Debian packages installed or absent. |
| `FLATPAK_APP` / `FLATPAK_BUNDLE` | Flathub applications or uploaded bundles. |
| `SYSTEMD_SERVICE` | Unit enabled/running state. |
| `SYSCTL_SETTING` | `/etc/sysctl.d/20-spire-cis-<id>.conf` plus live kernel state. |
| `APT_CONFIG` | Validated APT configuration drop-ins. |
| `DCONF_SETTING` | GNOME settings and optional mandatory locks. |
| `FIREWALL_RULESET` | Dedicated `table inet spire` nftables ruleset. |
| `LOCAL_ACCOUNT_POLICY` | Password quality, faillock, login defaults, and validated sudoers drop-in. |
| `TRUSTED_CA_CERTIFICATES` | CA certificates under the Spire-owned trust-store directory. |
| `NETWORK_PROFILE` | NetworkManager Wi-Fi, wired 802.1X, or WireGuard profile. |
| `USB_DEVICE_CONTROL` | usbguard policy. |
| `AUDITD_RULES` | Spire-owned auditd rules fragment. |

The built-in **Corporate Desktop Baseline** configures dconf wallpaper, privacy, idle-lock, and GDM banner settings. Wallpaper assets are uploaded through the policy form and served from the control plane with a SHA-256 digest.

For payload formats and per-engine verification commands, see sections 7 and 8 of the [production operations runbook](ADMIN_RUNBOOK.md).

## 4. Applications

The Applications page supports Debian package policies, Flathub applications, and uploaded `.flatpak` bundles.

- `REQUIRED` applications contribute to compliance and are reinstalled if removed.
- `AVAILABLE` applications appear in Spire Hub for user-initiated install and uninstall.

Uploaded bundles are stored under `SPIRE_BUNDLE_STORAGE_DIR`, defaulting to `/var/lib/spire/storage/bundles`. The agent downloads the bundle, verifies its SHA-256 digest, and installs it system-wide.

## 5. OIDC

Under **Settings → Single Sign-On**, configure:

- issuer URL;
- client ID and secret;
- scopes, normally `openid profile email groups`;
- groups claim name;
- local-login fallback;
- exact IdP group-to-role mappings.

The server uses OIDC discovery, authorization code flow, PKCE S256, nonce validation, issuer/audience validation, and signed ID-token verification. It identifies users by the IdP subject. If a new subject presents an email already owned by another account, sign-in is refused rather than attaching the identity by email.

OIDC state is stored in PostgreSQL and is safe across multiple server instances. MFA for OIDC users remains the identity provider's responsibility.

## 6. Vulnerabilities and agent rollout

The Vulnerabilities page imports Debian Security Tracker data and matches installed source-package versions by release codename. Automatic import is off by default. A `SUPER_ADMIN` can enable it; a `SECURITY_ADMIN` or `SUPER_ADMIN` can import immediately or upload an offline feed.

Under **Settings → Agent Rollout**, a `SUPER_ADMIN` can set a target version per ring and a minimum supported version. Agents verify the advertised size and SHA-256 before installation. The descriptor and package come from the same server, so this detects corruption, not control-plane compromise; packages are not independently signed by self-update.

## 7. Commands, terminal, and remote assistance

### 7.1 Queued commands and root PTY

`OPERATOR` and above can queue root shell commands or open a browser PTY. Queued command text, status, exit code, and output are stored. Interactive PTY auditing records session start and end; it does not record every keystroke or command entered in the terminal.

### 7.2 Attended remote assistance

The control plane sends a request over the device WebSocket. `spired`, not Spire Hub, discovers the active `seat0` user and attempts a 60-second `zenity` confirmation dialog. If approved, the current implementation enables GNOME Remote Desktop and returns an RDP address and generated PIN.

The prompt contains the requesting administrator name. It does not display the administrator IP or a granular requested-access scope, and Spire Hub has no Disconnect control. If `zenity` is absent, the current notification fallback does not provide a real interactive consent control; endpoint images intended for remote assistance should install `zenity` until that fallback is hardened.

In a multi-instance deployment, interactive PTY and remote assistance must reach the instance that owns the device WebSocket.

## 8. Lost-device actions and recovery keys

- **Lock:** `OPERATOR` and above can lock graphical sessions.
- **Lost mode:** `SECURITY_ADMIN` and above can lock sessions, install a marked `/etc/nologin`, and increase check-in frequency.
- **Recovery-key reveal:** `SECURITY_ADMIN` or `SUPER_ADMIN`, one administrator, mandatory reason, database and syslog audit, automatic rotation queued.
- **Wipe:** two different `SUPER_ADMIN` users, typed hostname confirmation, Ed25519-signed device-bound order, 24-hour approval window.

Recovery-key reveal is not dual control. Do not confuse its audit requirement with wipe's two-person approval.

## 9. Alerts, SIEM, and exports

**Settings → Alerts** supports signed JSON webhooks, Slack-compatible incoming webhooks, and SMTP. Delivery is queued in PostgreSQL, retried with backoff, and claimed safely across several server instances.

**Settings → SIEM & Logging** forwards RFC 5424 messages over UDP, TCP, or TLS. Configure the target using a scheme such as `udp://host:514`, `tcp://host:514`, or `tls://host:6514`, then use **Send test event**.

Compliance exports are available at:

- `GET /admin/compliance/export?format=csv`
- `GET /admin/compliance/export?format=json`

Browser sessions need CSRF tokens for state changes. Basic authentication and personal access tokens are intended for scripted API calls.

## 10. TPM attestation baselines and enforcement

**PCR Baselines** (sidebar → PCR Baselines, SECURITY_ADMIN and above) hold the
administrator-approved SHA-256 values for the attested PCRs (0, 2, 4, 7). Each verified TPM
quote is compared against the active baselines whose scope matches the device.

**Creating a baseline.** Two sources:

- *Manual values* — paste the 64-character hex SHA-256 digest for each PCR, on the PCR
  Baselines page.
- *Approve current measurements* — open a device whose latest quote is verified and use
  **Approve current measurements** in its attestation panel. This copies that device's
  quote-proven PCR values into a new baseline.

Optionally scope a baseline to device **tags** and/or a **ring**; an empty scope applies to
every device. Baselines are **immutable**: to change one, create a new version (the old
version is deactivated automatically and recorded as superseded). A tag-scoped operator may
only create baselines that include at least one of their assigned tags.

**Outcomes.** With a matching active baseline a device reads `BASELINE_MATCH`; with in-scope
baselines but no match it reads `BASELINE_MISMATCH` (the device panel lists the differing
PCRs and an alert fires); with no in-scope baseline it stays `ATTESTED`.

**Exceptions.** On the device attestation panel, SECURITY_ADMIN+ can grant a time-boxed
exception (mandatory reason, expiry at most 30 days). An unexpired exception makes the device
trusted regardless of its result; grant and expiry are audited.

**Enforcement** (PCR Baselines page, SUPER_ADMIN only): `crypto.attestation_enforcement` is
`off` (default), `warn`, or `enforce`, and `crypto.attestation_max_age_hours` (default 24)
sets how long a result stays fresh. In `enforce`, an untrusted device receives no sealed
network-profile secrets — affected policies arrive marked withheld and the agent skips them
without writing a blank credential or disturbing a working profile. The dashboard shows an
**Attestation Untrusted** count honouring your tag scope.
