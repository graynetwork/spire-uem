# SpireUEM Roadmap: Gaps Against Leading UEM Products

**Assessed:** 17 November 2026
**Compared with:** Microsoft Intune, Omnissa Workspace ONE UEM, Ivanti Neurons for UEM, IBM MaaS360, and Jamf Pro
**Status updated:** 19 November 2026. Phase 1 merged in PR #6 and Phase 2 in PR #8; see [Recommended order](#recommended-order). Items below carry a **Status** line where work has landed, and anything not listed there is still open.

No objective "top five" ranking exists. These five were chosen for enterprise market presence or category importance. Jamf Pro is included as the leading Apple-focused MDM.

## Summary

SpireUEM already has deeper native Linux configuration and security controls than most mainstream UEM products:

- Intune's Linux support is mainly enrollment, compliance reporting, and Edge-based Conditional Access.
- Workspace ONE has the broadest comparable Linux support, including profiles, internal packages, and sensors.
- Ivanti handles Linux through a separate agent platform focused on inventory and patching.
- MaaS360 has no general-purpose Linux endpoint management.
- Jamf Pro is Apple-only.

SpireUEM's largest gaps are not more Linux policy types. They are device trust, dynamic targeting, automation, inventory, certificate lifecycle, patch orchestration, integrations, and enterprise administration.

## Comparison

| Capability | SpireUEM | Intune | Workspace ONE | Ivanti | MaaS360 | Jamf Pro |
|---|---|---|---|---|---|---|
| Full Linux configuration | **Strong, Debian-specific** | Compliance only | Moderate | Inventory/patch only | None | None |
| Dynamic device groups | Rule-based groups (Phase 2) | Yes | Yes | Yes | Yes | Yes |
| Declarative policies | **Strong** | Strong outside Linux | Strong | Strong outside Linux | Strong outside Linux | Strong for Apple |
| Custom scripts and sensors | Versioned scripts and sensors (Phase 2) | Compliance scripts | Strong | Automation scripts | Windows/macOS scripts | Strong for macOS |
| Application catalog | Basic Debian/Flatpak | Strong | Strong | Strong outside Linux | Strong outside Linux | Strong for Apple |
| Patch campaigns | Staged campaigns with auto-halt (Phase 2) | Strong outside Linux | Limited on Linux | Strong Linux patching | Strong outside Linux | Strong for Apple |
| Compliance access gating | Reporting only | Entra Conditional Access | Access/Entra | Access/Sentry | Entra/IBM Verify | Entra/Google integrations |
| Certificate lifecycle | Built-in device CA and mTLS (Phase 1); no SCEP/EST | SCEP/PKCS/Cloud PKI | CA and credential profiles | Built-in/external CA | CA connector | SCEP/AD CS |
| Remote administration | Shell, PTY, RDP, lock/wipe | Remote Help | Workspace ONE Assist | Remote Control | Remote Support/TeamViewer | Remote Assist |
| Administrator delegation | Fixed roles plus tags | Custom roles/scopes | Roles and organization groups | Roles and spaces | Custom roles/groups | Roles and sites |
| Analytics | Operational dashboard | Advanced Analytics | Intelligence | DEX/Edge Intelligence | Dashboards and alerts | Inventory searches |
| Self-hosted/air-gapped | **Yes** | No | Linux is SaaS-only | No | No | Limited/on-prem option |

## Missing entirely

### 1. Dynamic groups and saved fleet queries

Every comparison product can derive groups from inventory or compliance state. SpireUEM assigns policies through manually maintained tags and rings.

- Rules such as `os_version < 12.8`, `has_cve("CVE-...")`, `last_seen > 7d`, or `compliance != compliant`.
- Nested AND/OR conditions.
- Include and exclude rules.
- Preview of affected devices before activation.
- Dynamic groups as policy, application, patch, alert, and reporting targets.
- Membership history explaining why a device entered or left a group.

This should be the first major control-plane feature because it improves almost every existing feature.

**Status: done in Phase 2 (PR #8).** Rules compile to parameterised SQL over inventory, sensor and compliance attributes, with nested conditions, include/exclude, preview, membership history, and policy targeting. Alerts and reports can't target groups yet; policies (including application installs), patch campaigns and workflows can.

### 2. Device certificate and PKI lifecycle

SpireUEM can distribute trusted CA certificates, but it cannot issue, renew, revoke, or use certificates as device identities.

- Per-device certificates issued through SCEP or EST.
- Automatic renewal and revocation.
- Mutual TLS for agent REST and WebSocket connections.
- Certificate pinning or trust-on-enrollment with controlled rotation.
- Certificate profiles for Wi-Fi, wired 802.1X, VPN, and browser authentication.
- A CA abstraction supporting an internal CA and external enterprise PKI.

All five products have certificate-management facilities. This would also close SpireUEM's bearer-token and first-contact wipe-key trust gaps.

**Status: partly done in Phase 1 (PR #6).** A built-in device CA issues one certificate per device, with renewal, revocation, an `off`/`optional`/`required` mTLS mode and optional server-certificate pinning. Still open: SCEP/EST, external enterprise PKI, and certificate profiles for Wi-Fi, 802.1X, VPN and browsers.

### 3. Conditional-access and quarantine integrations

SpireUEM records compliance and attestation results but does not use them to control access or policy-secret delivery.

- Approved TPM PCR baselines with explicit versioned exceptions.
- A rule engine that can require attestation, encryption, patch level, or policy compliance.
- Quarantine state with a restricted policy set.
- Refusal to send network credentials or other sealed secrets to an untrusted device.
- Compliance exports or connectors for Microsoft Entra, Authentik, reverse proxies, NAC, and VPN systems.
- Signed compliance webhooks and a read-only device-posture API.

SpireUEM should integrate with access systems rather than build its own identity proxy.

### 4. Reusable scripts and custom sensors

Queued root commands are useful for one-off work, but they are not a managed automation system.

- Versioned Bash or Python scripts.
- Parameters and sealed secret inputs.
- Timeouts, output limits, interpreter restrictions, and signatures.
- Execution as root or the active user.
- Scheduled, event-triggered, and on-demand execution.
- Typed sensor results: string, integer, Boolean, date, and structured JSON.
- Inventory fields and dynamic-group membership derived from sensor results.
- Install and rollback scripts for custom policies.

Workspace ONE's sensors and Jamf's scripts and extension attributes are good reference models.

**Status: done in Phase 2 (PR #8).** Versioned scripts with hash checks, parameters and sealed secrets, timeouts and output caps, root or active-user execution, typed sensors feeding attributes, and a `SCRIPT_POLICY` type with detect, remediate and remove scripts. Scheduled and event runs come from workflows. Script signatures are still open.

### 5. Rich hardware and software inventory

SpireUEM records packages, source packages, OS, kernel, hostname, hardware UUID, and active-session information.

- CPU, memory, motherboard, BIOS/UEFI, firmware, TPM, disks, encryption, battery, GPU, monitors, and network interfaces.
- Installed package origin, architecture, install date, available version, and repository.
- Kernel modules, listening services, local accounts, certificates, USB devices, and security products.
- Inventory history and field-level change detection.
- Custom attributes populated by sensors.
- Fleet-wide search and CSV/JSON exports.

Inventory should feed dynamic groups instead of becoming a separate passive database.

**Status: done in Phase 2 (PR #8).** Hardware, network, software and security facts, change history, sensor-backed custom attributes, fleet search and CSV/JSON export. Collectors have only been tested with fakes, not across varied real hardware.

### 6. Custom roles and organization scopes

SpireUEM has fixed roles and tag scopes.

- Custom roles built from named permissions.
- Separate rights for command execution, PTY, recovery-key reveal, policy edits, application deployment, wipe, and audit export.
- Organization units or sites with delegated administrators.
- Optional two-person approval for security-policy, rollout, and mass-action changes.
- Service accounts with API-specific roles, separate from human PATs.

Multi-tenancy should wait unless SpireUEM intends to support MSPs.

### 7. Endpoint-security connectors

SpireUEM should consume EDR state rather than build an EDR product. Candidate integrations:

- Microsoft Defender for Endpoint
- CrowdStrike
- SentinelOne
- Wazuh
- Elastic Defend
- ClamAV for smaller self-hosted deployments

Normalize their state into device risk, active threats, engine health, and last scan, so it can drive dynamic groups, alerts, and quarantine.

## Existing capabilities that need expansion

### 8. Patch campaigns

SpireUEM has patch windows, rings, immediate patching, Debian CVE matching, and patch telemetry.

- "Remediate this CVE" campaigns that calculate affected devices automatically.
- Deadlines, deferrals, reboot policy, blackout periods, and user notifications.
- Canary promotion based on success thresholds.
- Pause and automatic halt when failure rates exceed a threshold.
- Version pinning and rollback where Debian packages permit it.
- Per-package exclusions and temporary risk acceptance.
- Campaign progress, failure classification, and mean-time-to-remediate reporting.

**Status: mostly done in Phase 2 (PR #8).** CVE and package campaigns, canary -> pilot -> production promotion, automatic halt, blackout windows, deadlines, deferrals, reboot policy and time-limited risk acceptance, tested with real `apt` on a lab VM. Still open: an admin rollback action, version pinning, and mean-time-to-remediate reporting.

### 9. Application lifecycle management

- Package metadata, icons, descriptions, categories, ownership, and support links.
- Explicit version targeting and pinning.
- Dependencies and supersedence.
- Detection rules independent of package name.
- Install and uninstall scripts.
- Phased deployment and rollback.
- Approval workflows for self-service applications.
- Adoption, failure, and stale-version reports.
- Optional curated application recipes rather than hosting every binary.

### 10. Automation and remediation workflows

Declarative policies correct some drift, but there is no general event-action engine.

```text
WHEN device has critical CVE
AND device is online
AND device is in CANARY
THEN schedule patch
ELSE notify security
```

Triggers: enrollment or approval, inventory change, compliance transition, CVE discovery, device offline, failed patch or update, attestation failure, and user login, startup, or network change.

Actions: assign or remove policy, run a managed script, change ring or tag, open a patch campaign, and notify, quarantine, lock, or request approval.

Keep the first version deterministic. A visual workflow editor can come later.

**Status: done in Phase 2 (PR #8).** A durable event log processed once across servers, with triggers, conditions in the group rule language, and actions including scripts, tags, ring, groups, alerts, lock, quarantine, approvals and `start_campaign`. Loop suppression, cooldowns, an action budget and dry runs limit it. No admin pages yet; it's managed through the JSON API.

### 11. Stable automation API

SpireUEM has REST handlers, PATs, and alert webhooks, but no documented, versioned public administration API.

- Versioned JSON endpoints for devices, groups, policies, applications, campaigns, actions, and reports.
- OpenAPI documentation.
- Idempotency keys for mutations.
- Pagination, filtering, and consistent error objects.
- Service-account credentials with granular scopes.
- Event webhooks for enrollment, compliance, patching, policy changes, and device lifecycle.
- Terraform or Ansible integration only after the API stabilizes.

### 12. Remote-support hardening

- Fail closed when `zenity` is unavailable. Notification delivery must never count as consent.
- Route PTY and remote-assistance streams between server instances.
- Session duration and inactivity limits.
- Optional view-only mode.
- Clipboard and file-transfer controls.
- Clear on-device indicator and user-controlled disconnect.
- Complete operator, target, start, end, and consent audit records.
- Optional session recording with explicit retention and privacy controls.

**Status: first item done in Phase 1 (PR #6).** Only an explicit Yes in the `zenity` dialog approves; otherwise the request is refused with `CONSENT_UNAVAILABLE`. The rest of this list is open, and the PIN sent to the administrator is still never applied to GNOME Remote Desktop.

### 13. Reporting and operational analytics

- Scheduled reports and email delivery.
- Compliance and vulnerability trends by group.
- Patch success, deployment failure, and reboot-debt trends.
- Agent-version adoption and unsupported-agent reports.
- Device lifecycle and inactive-device reports.
- Exception and risk-acceptance expiry reports.
- Exportable dashboard queries.
- API and webhook delivery for reporting systems.

A full digital-employee-experience product is unnecessary. Basic boot, CPU, memory, disk-health, crash, and network-quality telemetry would still help operators.

### 14. Automated enrollment

Dynamic enrollment tokens exist, but the standard bootstrap cannot consume them.

- `--enrollment-token` support in the bootstrap and agent.
- One-time and bounded-use tokens.
- Preassigned group, tags, ring, and policy bundle.
- Hardware UUID plus generated key binding.
- Cloud-init, preseed, and image-building examples.
- Optional approval requirement depending on token policy.
- Token rotation and enrollment audit history.

**Status: done in Phase 2 (PR #8).** Tokens are read from a file or environment variable, with bounded uses, optional approval, hostname limits, token-assigned tags, rotation, enrollment history, rate limiting and `spired --reset-identity` for golden images. Cloud-init and preseed examples are still open.

### 15. Additional Linux distributions

Debian depth is a differentiator; expanding too early would weaken it. Once policy engines have clean platform interfaces, add:

1. Ubuntu LTS
2. Debian derivatives
3. RHEL, Rocky Linux, and AlmaLinux
4. SUSE, only if demand justifies it

Use separate package, firewall, network, compliance, and desktop adapters instead of distribution conditionals inside the Debian engines.

## Recommended order

### Phase 1: secure the trust chain (done, PR #6)

1. Device certificates, renewal, and mTLS.
2. Approved PCR baselines and attestation-based secret gating.
3. Independently signed updates with rollback.
4. Fail-closed remote-assistance consent.

Remaining Phase 1 gaps: a device whose certificate has lapsed can get a new one with its token alone, and rollback and real TPM paths have only been tested with fakes. PR #7 seals EAP-TLS client keys at rest, but PCR enforcement doesn't yet recognise them: an untrusted device still receives the sealed client-key envelope (ciphertext, not plaintext), and a policy whose only secret is a client key isn't flagged as withheld.

### Phase 2: manage existing capabilities at scale (done, PR #8)

5. Rich inventory and custom attributes.
6. Dynamic groups and saved queries.
7. Reusable scripts and sensors.
8. Automated enrollment.
9. Patch campaigns and automatic rollout halting.
10. General remediation workflows.

### Phase 3: enterprise integration

11. Stable administration API, service accounts, and event webhooks.
12. Conditional-access and EDR connectors.
13. Custom roles and organization scopes.
14. Application lifecycle improvements.
15. Scheduled reporting and operational analytics.
16. Additional Linux distributions.

## Out of scope for now

- Mobile application containers and mobile DLP.
- Apple Business Manager, APNs, Activation Lock, or Apple supervision.
- Windows Autopilot, BitLocker, Defender policy, or Windows Update for Business.
- Android Enterprise work profiles, kiosk APIs, and managed Google Play.
- Geofencing and continuous location collection.
- A proprietary EDR engine.
- An AI assistant before the inventory, API, and workflow model is complete.
- MSP multi-tenancy unless it becomes an explicit product goal.

## Sources

- Microsoft: [Intune overview](https://learn.microsoft.com/en-us/intune/fundamentals/what-is-intune), [Linux management guide](https://learn.microsoft.com/en-us/intune/fundamentals/platform-guide-linux), [advanced capabilities](https://learn.microsoft.com/en-us/intune/fundamentals/advanced-capabilities)
- Omnissa: [Workspace ONE UEM](https://www.omnissa.com/products/workspace-one-unified-endpoint-management/), [Linux profiles](https://docs.omnissa.com/LinuxDeviceManagement-V2410/LinuxProfiles), [Linux application management](https://docs.omnissa.com/LinuxDeviceManagement-V2410/LinuxAppManagement), [Linux sensors](https://docs.omnissa.com/LinuxDeviceManagement-V2410/SensorsforLinuxBasedDevices)
- Ivanti: [Neurons for UEM](https://www.ivanti.com/en-gb/products/ivanti-neurons-for-unified-endpoint-management), [OS and capability matrix](https://help.ivanti.com/ht/help/en_US/CLOUD/vNow/compatibility.htm), [Linux patching](https://help.ivanti.com/ht/help/en_US/CLOUD/vNow/patch-linux.htm)
- IBM: [MaaS360 Endpoint Management](https://www.ibm.com/products/maas360/endpoint-management), [supported operating systems](https://www.ibm.com/docs/en/maas360?topic=devices-supported-in-maas360-based-operating-system), [administrative roles](https://www.ibm.com/docs/en/maas360?topic=administrators-access-roles-rights-maas360-portal)
- Jamf: [device enrollment guide](https://developer.jamf.com/jamf-pro/docs/jamf-pro-device-enrollment-guide), [App Installers](https://learn.jamf.com/bundle/jamf-pro-documentation-current/page/App_Installers.html), [Jamf Pro API](https://developer.jamf.com/jamf-pro/docs/jamf-pro-api-overview)
