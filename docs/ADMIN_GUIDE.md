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

`OPERATOR` and `SECURITY_ADMIN` can be limited to devices carrying specified tags. Their device lists, dashboard totals, vulnerability counts, audit events, and device-targeted actions are filtered server-side. An empty allowed-tag list is unrestricted. A tag-scoped admin can create or change a policy or application only if every target tag is one of their tags (fleet-wide targeting is refused) and every target group is one they may edit; they cannot toggle, edit or delete a policy that reaches outside their tags. `SUPER_ADMIN` and `AUDITOR` are not tag-scoped.

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

**Settings → Enrollment Tokens** (SUPER_ADMIN) creates `spire_tok_...` tokens for automated onboarding. Each token carries a description, target tags, maximum uses (`1` = one-time, `0` = unlimited), expiry, deployment ring, an optional **require approval** flag (default off — the device auto-approves), and an optional **allowed hostname pattern** (a glob such as `lab-*`; blank = any hostname). The creator is recorded (`created_by`).

Tokens are stored **hashed**; the secret is shown **once** at creation (and once again after rotation). **Rotate** generates a fresh secret while keeping the token's settings and history — the old secret stops working immediately. **Revoke** disables the token. Each token's page lists its **enrollment history**: device, hardware UUID, hostname, time, source IP, and result (approved, pending, or refused with a reason).

Install an endpoint with a token using the bootstrap (see the onboarding runbook): `--enrollment-token-file PATH` (preferred; the file is `0600` and consumed once) or `--enrollment-token VALUE` (works, but prints a warning that it is visible in the process list and shell history). The agent registers in one request that binds the hardware UUID, its enrollment key, and a CSR for its device certificate; a token can never let a second machine take over an existing device record.

Supported token ring values are `CANARY`, `BETA`, `PILOT`, and `PRODUCTION`. Revoked, expired, exhausted, unknown, hostname-mismatched, or key-conflicting registrations all receive the same uniform `401 Unauthorized` (so token existence is not revealed); the specific reason is recorded only in the token's history. Repeated failed attempts from one IP are rate limited (`429`).

Token create, rotate, and revoke, and every registration attempt, are audited.

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

## 4a. Device groups and saved fleet queries

The **Groups** page defines dynamic device groups and saved fleet queries. Viewing is open to
`AUDITOR`+; creating, editing and deleting require `SECURITY_ADMIN`+.

A group has:

- a **name** and optional **description**;
- a **kind** — `target` (the group can be used to target policies and applications) or
  `query` (a saved fleet query, usable only for viewing and export);
- an optional **rule** (JSON); and
- static **include** and **exclude** device-ID lists.

Membership is `(rule matches OR device is included) AND device is NOT excluded`. The exclude
list wins over both the rule and the include list.

**Writing a rule.** A rule is a JSON tree of `all` / `any` / `not` combinators and leaf
conditions `{"field":..., "op":..., "value":...}`, capped at 6 levels deep and 64 leaves.
Example — approved devices that have not checked in for a week and have open high-urgency CVEs:

```json
{"all":[
  {"field":"device.status","op":"eq","value":"APPROVED"},
  {"field":"device.last_checkin_at","op":"older_than","value":"7d"},
  {"field":"cve.open_high_or_critical","op":"gt","value":0}
]}
```

Selectable fields are a fixed list: the device columns (`device.hostname`, `device.status`,
`device.tags`, `device.patch_ring`, `device.agent_version`, `device.last_checkin_at`,
`device.attestation_status`, `device.os_name`, `device.kernel_version`,
`device.release_codename`, `device.pending_updates`, `device.security_updates`,
`device.reboot_required`, `device.ws_connected`, `device.compliance`), CVE state (`cve.id`,
`cve.open_high_or_critical`) and `attr.<key>` for any device attribute. Operators depend on
the field's type; `device.tags` uses `contains_any` / `contains_all`, datetimes use
`before` / `after` / `older_than` / `newer_than` (durations like `7d`, `12h`), and any field
supports `exists` / `missing`. An unknown field, an operator that does not fit the type, an
over-deep or over-wide tree, or a `matches` pattern Postgres cannot compile is rejected with a
clear error before the group is saved.

**Preview** evaluates the current rule and shows the match count and the first 50 hostnames
before you save, scoped to your own tags if you are a scoped admin.

**Using a group for targeting.** On the policy form, add one or more target groups. A policy
with target groups is applied to a device only when its existing tag/ring rules match AND the
device is a member of at least one of the listed groups. A policy with no groups is unchanged
from before this feature. When a device gains or loses membership, assignment follows at its
next check-in; a device that leaves every targeted group has the policy revoked through the
normal cleanup path. A group that is referenced by a policy cannot be deleted — the server
lists the referencing policies instead.

**Filtering.** The Devices list, the Vulnerabilities page and the compliance export each
accept a `group` filter to narrow their results to a group's members (scoped to your tags).

**Tag scoping.** If your account is tag-scoped, every group you create carries an implicit
"device has one of my tags" filter, you see only in-scope members and counts, and you can edit
only groups created by a scoped admin whose scope overlaps yours — never a group created by an
unscoped administrator.

**Recompute and reliability.** Membership is recomputed for a device when it checks in, for a
group when you save it, and for all groups on a periodic sweep (default every 5 minutes). The
group page records enter/leave history with a reason. If a group's rule fails to evaluate, the
last good membership is kept (the group is never silently emptied) and the error is shown on
the group's row.

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

Under **Settings → Agent Rollout**, a `SUPER_ADMIN` can set a target version per ring and a minimum supported version. Agents verify the advertised size and SHA-256 before installation, AND an independent Ed25519 release signature when a signed manifest is published beside the package. The signing key is held off the control plane and the public key is pinned inside the agent package, so a compromised control plane cannot push a forged agent to agents that require signed updates. Agents require signed updates by default; see the [production operations runbook](ADMIN_RUNBOOK.md) for signing a release, key rotation, and the unsigned-to-signed transition.

Each device's row shows its agent version and self-update status. A failed or refused update shows **FAILED**; an update whose new agent never confirmed healthy and was automatically reverted shows **ROLLED_BACK → previous version**. Both raise an alert through the configured channels (`agent_update_failed`), a signature/verification failure and a rollback at critical severity.

## 6A. Inventory

Each agent collects a rich hardware, software, network, and security snapshot and sends it on a check-in **at most once per `inventory_interval`** (agent config, default 6 hours). A fresh report is forced on the agent's first check-in after start and when an administrator requests a refresh. Most check-ins carry no inventory, so this does not grow the ordinary check-in payload.

**What is collected.** Hardware: CPU model/cores/threads, memory, system and board vendor/product/serial, BIOS vendor/version/date, TPM presence and version, disks (size, model, rotational, transport, whether LUKS-encrypted), battery capacity and health, GPUs, connected monitor count, and virtualisation. Network: interfaces with MAC/state/addresses, default gateway, DNS servers, and the primary IPv4/MAC. Software: package count and per-package name/version/arch/origin/install-time, kernel modules, listening TCP/UDP sockets with the owning process, local accounts with UID ≥ 1000 and sudo/admin membership (**never password hashes**), CA certificates in the system trust store (subject/expiry/SHA-256), and USB devices. Security: detected products from a fixed list (clamav, wazuh-agent, falcon-sensor, mdatp, elastic-agent, sentinelone, osquery) with installed/running state, firewall-active (nftables ruleset present), auditd, and usbguard. The agent reads only this metadata; it never reads file contents, keys, or user files.

**Where it is stored.** Scalar facts become typed device attributes under a fixed key catalogue (for example `hw.memory_mb`, `hw.bios.version`, `hw.disk.encrypted_all`, `net.primary_ipv4`, `sec.firewall_active`, `sw.package_count`). The large lists (packages, kernel modules, listening sockets, local accounts, CA certificates, USB devices) go to dedicated tables that are replaced wholesale on each report. A device that has never reported (an older agent, or one that has not yet reached its first interval) shows **"No inventory reported"**.

**Change history.** The device page shows a bounded, field-level history (the most recent 500 changes per device) of attribute changes and list membership changes — a new listening port, a new local admin, a package install or removal — each marked added, removed, or modified.

**Device page.** Each device detail drawer shows the scalar facts, the collapsible lists, and the change history. `OPERATOR` and above see a **Request Inventory Refresh** button that queues a refresh over the existing device command path; the agent collects and sends a fresh report on its next check-in. The action is tag-scoped and audited (`INVENTORY_REFRESH`).

**Fleet search and export.** The **Inventory** sidebar page (any authenticated role) filters devices by an attribute key/operator/value, by installed package name, by listening port, or by local admin username. Results and counts respect the admin's tag scope. `AUDITOR` and above can export the current filter as CSV or JSON from `GET /admin/inventory/export?format=csv|json`; the export is tag-scoped and audited (`INVENTORY_EXPORT`), so a scoped operator can never export a device outside their tags.

## 7. Commands, terminal, and remote assistance

### 7.1 Queued commands and root PTY

`OPERATOR` and above can queue root shell commands or open a browser PTY. Queued command text, status, exit code, and output are stored. Interactive PTY auditing records session start and end; it does not record every keystroke or command entered in the terminal.

### 7.2 Attended remote assistance

The control plane sends a request over the device WebSocket. `spired`, not Spire Hub, discovers the active `seat0` user and shows a 60-second `zenity` Yes/No dialog. Only an explicit **Yes** approves. **No**, closing the dialog or the timeout returns `REJECTED_BY_USER`. If approved, the current implementation enables GNOME Remote Desktop and returns an RDP address and a generated PIN.

The prompt contains the requesting administrator name. It does not display the administrator IP or a granular requested-access scope, and Spire Hub has no Disconnect control. If `zenity` is not installed or cannot start, the request fails closed with `CONSENT_UNAVAILABLE` and the user receives an informational notification that it was refused. A notification is never treated as consent. Endpoint images intended for remote assistance must install `zenity`.

The generated PIN is currently not written into GNOME Remote Desktop's credentials, so it cannot be used to sign in. Treat the RDP details as incomplete until that is fixed.

A root-owned override (`SPIRE_REMOTE_ASSIST_DECISION` in the service environment or `/etc/spire/remote-assist-decision`) set to `APPROVE` bypasses the prompt. It exists for headless testing, is logged when used, and must not be present on production endpoints.

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


## Reusable scripts, custom sensors, and script-based policies

These features are managed through the admin JSON API (routes under `/admin`); there is no
dedicated HTML page yet. Role requirements and tag scoping are enforced by the server.

### Scripts

A script has a fixed interpreter (`bash` or `python3` only), a run-as identity (`root` or
`active_user`), a timeout (default 300 s, max 3600 s), an output cap (default 64 KiB, max
1 MiB), and a parameter schema. Parameter names must match `^[A-Z][A-Z0-9_]{0,31}$`; a
parameter may be `string`, `integer` or `boolean`, required, defaulted, and marked `secret`.

- `GET /admin/scripts`, `GET /admin/scripts/{id}` — list / inspect (any role that can read).
- `POST /admin/scripts` — create (SECURITY_ADMIN+). Body: `name`, `interpreter`, `run_as`,
  `timeout_seconds`, `max_output_bytes`, `content`, `params`.
- `POST /admin/scripts/{id}` — change metadata only (SECURITY_ADMIN+).
- `POST /admin/scripts/{id}/versions` — add a new immutable version with new content/params
  (SECURITY_ADMIN+). Editing content is always a new version; old versions keep running where
  they were pinned.
- `POST /admin/scripts/{id}/versions/{versionID}/current` — mark a version current.
- `DELETE /admin/scripts/{id}` — delete the script and its history.

Editing a script never mutates an existing version. Each version carries its own sha256, which
the agent verifies before running.

### Running a script

`POST /admin/scripts/{id}/run` (OPERATOR+). Body selects a target — `device_ids`, `tags`, or
`ring` — with `params` and an optional `version_id` (defaults to the current version). A
tag-scoped operator's target is intersected with their allowed tags, and only APPROVED devices
run. The run is reported per device with status, exit code, capped stdout/stderr and duration;
`GET /admin/devices/{id}/script-runs` shows recent runs for a device. Secret parameter values
are stored sealed, delivered only to the target device, and never shown or logged again.

Parameters reach the script only as environment variables named `SPIRE_PARAM_<NAME>`. Inside a
bash script read `"$SPIRE_PARAM_PORT"`, inside python `os.environ["SPIRE_PARAM_PORT"]`. Values
are passed literally, so a value such as `$(reboot)` is just that string, never executed.

### Sensors

A sensor runs a script version on a schedule and stores its typed result as the device
attribute `sensor.<name>`. Sensor names match `^[a-z][a-z0-9_]{0,47}$`, the interval is at
least 15 minutes, and the return type is `string`, `integer`, `boolean`, `datetime` (RFC 3339)
or `json`. A non-zero exit or output that does not parse to the declared type records an error
and leaves the device's last good value in place.

- `GET /admin/sensors`, `POST /admin/sensors` (create), `POST /admin/sensors/{id}` (update,
  name is immutable), `DELETE /admin/sensors/{id}` — SECURITY_ADMIN+.
- `GET /admin/devices/{id}/sensors/{name}` — a device's recent readings.

Disabling or deleting a sensor, or a device leaving the sensor's target tags/ring, removes that
device's `sensor.<name>` attribute at its next check-in. A sensor can never overwrite an
inventory key: each source owns only the keys it writes.

### SCRIPT_POLICY

Create a policy of type `SCRIPT_POLICY` whose payload references script version ids for
`detect` (exit 0 means compliant), optional `remediate`, and optional `remove`. The agent runs
detect; if non-compliant and a remediate step is set it runs remediate and detects again,
reporting compliance from that second detect. On unassignment the agent runs `remove` once if
set. If a referenced version has been deleted the policy reports FAILED and does nothing, so a
deleted script never leaves a device in an unknown state.

## Automation and remediation workflows

A **workflow** reacts to something that happens in the fleet, or runs on a schedule, and takes
bounded actions on each matching device. `SECURITY_ADMIN`+ create and edit workflows; `AUDITOR`+
can view workflows and their run history. A tag-scoped admin's workflow only ever fires for
devices in their tag scope, and can only make tag/ring/group changes inside that scope.

A workflow has:

- **A trigger** — exactly one of:
  - an **event** (one kind, with an optional filter on event fields), chosen from: device
    enrolled, device approved, inventory attribute changed, compliance changed, CVE matched,
    device offline, patch failed, agent update failed, attestation failed, baseline mismatch,
    agent started, active session changed, primary address changed. Example filter:
    `{"urgency":"high"}` on a CVE-matched trigger, or `{"key":"sec.firewall_active"}` on an
    attribute-changed trigger.
  - a **schedule** — a standard 5-field cron expression evaluated once per minute, over a target
    (a dynamic group, a tag set, or a ring).
- **A condition** (optional) — a rule in the same language as dynamic groups, evaluated against
  the candidate device at run time. If it is false, the `else` actions run instead of `then`.
- **`then` / `else` actions** — any of: add tag, remove tag, set ring, add the device to / remove
  it from a group's static include list, run a library script version (with parameters), send an
  alert, lock the device's sessions, quarantine (adds the configured quarantine tag, default
  `quarantine`), or require approval.

**Require-approval** pauses the run: the actions after it do not run until a `SECURITY_ADMIN`
approves (from the pending-approvals list) or rejects it, or it expires (default 24h), after
which the remaining actions are abandoned.

**Scheduled and agent-start script runs.** A `run_script` action on a scheduled workflow queues
the run with the `scheduled` trigger; on an "agent started" workflow it uses the `agent_start`
trigger. This is how you run a script on every device in a group each night, or once each time an
agent restarts.

**Safety.** Workflows are deterministic and bounded. A change a workflow makes never triggers
another workflow (loop suppression). Each workflow is rate-limited per device by a **cooldown**
(default 1 hour) and the whole fleet is bounded by a **global per-minute action budget**. Turn on
**dry run** to see what a workflow *would* do (recorded in its run history) without changing
anything. Every run and every action is written to the audit log with actor `workflow:<name>`.

A device that is revoked between the event and the action is skipped; a run_script action whose
script version was deleted fails and is recorded (it never leaves the device in an unknown
state).

The admin surface is a JSON API: `GET/POST /admin/workflows`, `POST /admin/workflows/{id}`,
`POST /admin/workflows/{id}/toggle`, `DELETE /admin/workflows/{id}`, `GET /admin/workflows/runs`,
`GET /admin/workflows/approvals`, and `POST /admin/workflows/approvals/{id}/approve|reject`.

## 11. Patch campaigns, risk acceptance, and automatic halting

A patch campaign rolls a set of package upgrades out to a target set of devices in ordered
stages, halting automatically if too many devices fail. Campaigns are managed by
`SECURITY_ADMIN` and above; a tag-scoped admin sees and controls only campaigns within their
tags and can target only their own devices.

**Create a campaign** (`POST /admin/campaigns`). Choose exactly one target:
- a dynamic group (`"target_kind":"group","group_id":"..."`),
- a list of CVE ids (`"target_kind":"cve","cve_ids":["CVE-2024-...", ...]`) — each targeted
  device gets work to bring the affected source package to the CVE's fixed version, only when a
  fix is available; a CVE with no fix yields no work,
- or explicit packages (`"target_kind":"packages","packages":["curl", ...]`) — every device that
  has one of those packages installed is upgraded to the latest available.
Optionally limit with `target_tags` and `target_ring`. Set `stages` (or accept the default
CANARY -> PILOT -> PRODUCTION), `reboot_policy` (`never` / `notify` / `force`), `max_deferrals`,
an optional `deadline_at`, a `blackout_cron` + `blackout_duration_minutes`, and
`respect_maintenance_window`. Per-campaign `package_exclusions` drop named packages from the
work. Package names and versions are validated against Debian rules at creation; an invalid name
is rejected.

**Stages.** Each stage has a minimum device count, a success threshold (e.g. 95%), a soak time,
and a failure-halt threshold (a percentage of reporting devices and/or an absolute count).
A stage promotes to the next automatically once its success threshold holds for the soak time
(set a stage's promotion to manual to require a click instead). If the failure-halt threshold is
exceeded the whole campaign halts automatically, an alert is raised, and nothing further is
dispatched until you resume it — halting always takes precedence over promotion.

**Controls.** `POST /admin/campaigns/{id}/start|pause|resume|cancel`. Resume clears a halt as
well as a pause. `GET /admin/campaigns/{id}` returns the campaign, its per-device work, a report
(device counts by stage and state, failure classes) and its event log.
`GET /admin/campaigns/{id}/export?format=csv|json` exports the per-device work, tag-scoped.

**How devices receive work.** There is nothing to trigger by hand. After you start a campaign,
each device picks up its work at its next check-in when the campaign is running, no blackout
window is active, the campaign's current stage matches the device's patch ring (a `CANARY` stage
reaches only CANARY devices), and, if the campaign respects maintenance windows, the device is
inside one. A server loop (every minute by default) then advances the campaign: it promotes a
stage after its soak time, halts on failures, and completes the campaign. **A stage only advances
once every device in it has a result**, so devices that are offline or have deferred keep it open.
A device that does not run the new agent never reports and is counted as failed (`UNSUPPORTED`)
after 24 hours.

**End-user deferral.** Before installing, the active user is notified. If the server still allows
deferral, Spire Hub shows an "Updates scheduled" row with a **Defer** button for about a minute; a
deferral postpones that device's install by 4 hours (never past the deadline), up to
`max_deferrals` times. After the deadline (if set) or once deferrals are used up, the install
proceeds without a Defer button. Reboot policy: `never` does not reboot; `notify` tells the user a
restart is needed; `force` only notifies before the deadline, and at or after it warns the user and
restarts the computer five minutes later. If the agent is restarted mid-install the device is
reported `INTERRUPTED` (not success).

**Rollback.** The agent records each package's previous version when it upgrades it, and the
rollback planner only ever targets packages the campaign upgraded, and only to a version that is
still available from the device's repositories. **There is no admin rollback action yet**; it is
not available from the UI or API in this release.

**Risk acceptance and exclusions** (`/admin/risk-acceptances`). Accept a CVE and/or package for
all devices, a group, or a tag set, with a required reason and an expiry (maximum 180 days).
Accepted findings are excluded from new campaign work and shown as "accepted" rather than hidden;
on the **Vulnerabilities** page an accepted CVE keeps its row with an "accepted" badge, the reason,
the expiry date and who accepted it ("accepted on N of M" when only some hosts are covered), and the
header counts open and accepted CVEs. The page only counts your own devices if you are tag-scoped.
An acceptance stops applying the moment it expires and the finding is open again. A tag-scoped admin may only accept risk within
their own tags and may not create a fleet-wide acceptance. Every create, control action and
deletion is audited with the acting admin.
