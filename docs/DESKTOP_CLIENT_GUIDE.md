# Spire Hub Desktop Client and Field Troubleshooting Guide

Spire Hub (`org.spire.hub`) is the unprivileged GTK4/Libadwaita interface installed on managed Debian workstations. The UI is implemented in Python with PyGObject and launched by `/usr/bin/spire-hub`; the package depends on Python 3, GTK4, and Libadwaita GI bindings.

## 1. Desktop integration

- Application ID: `org.spire.hub`
- Launcher: `/usr/bin/spire-hub`
- Python UI: `/usr/lib/spire/spire-hub.py`
- Desktop entry: `/usr/share/applications/spire-hub.desktop`
- Icon: `/usr/share/icons/hicolor/scalable/apps/spire-hub.svg`
- Categories: `System;Settings;PackageManager;`

Spire Hub runs as the active graphical user and never invokes `sudo`. Privileged work is requested through `spired` over `/run/spire/agent.sock`.

## 2. User features

### 2.1 Security Compliance

The Security Compliance view displays the latest state exposed by the local agent:

- TPM quote status and Secure Boot evidence;
- whether a LUKS recovery key has been escrowed;
- latest CIS score, when available;
- assigned baseline-policy compliance;
- required-application installation status;
- last check-in time.

An `ATTESTED` TPM status means the server accepted a fresh, correctly signed quote and found a nonzero signed PCR 7. SpireUEM does not currently compare PCRs with an administrator-approved firmware or boot baseline.

### 2.2 App Catalog

`AVAILABLE` applications appear with Install, Open, or Remove controls. `REQUIRED` applications appear in the compliance view and cannot be removed through the optional catalog. The user supplies no administrator password; `spired` validates the policy ID against the server-provided catalog before performing the privileged operation.

### 2.3 Remote assistance

Remote-assistance consent is not implemented inside Spire Hub. When an administrator requests assistance, the request reaches `spired` over the device WebSocket. The daemon discovers the active `seat0` user and attempts to show a 60-second `zenity` confirmation dialog containing the administrator name. On approval it enables GNOME Remote Desktop and returns an RDP address and generated PIN to the administrator.

The current prompt does not show the administrator IP or granular access scope, and Spire Hub has no Disconnect button. Endpoint images intended to use remote assistance should include `zenity`; the current notification-only fallback does not provide a genuine clickable consent choice and needs hardening.

## 3. UNIX-socket API

The socket is created at `/run/spire/agent.sock` with mode `0666`. Authorization does not rely on mode bits: `spired` obtains the peer UID with Linux `SO_PEERCRED` and permits root or the active `seat0` user. Other local users receive HTTP 403.

| Method and path | Purpose |
|---|---|
| `GET /v1/status` | Current local status, compliance groups, catalog summary, TPM evidence, and check-in time. |
| `POST /v1/sync` | Trigger an immediate agent check-in. |
| `GET /v1/catalog` | List assigned application policies and current installation state. |
| `POST /v1/install` | Install an approved policy. JSON body: `{"policy_id":"<id>"}`. |
| `POST /v1/uninstall` | Uninstall an optional approved policy. JSON body: `{"policy_id":"<id>"}`. |

Remote-assistance request and response frames use the control-plane WebSocket; there is no `/v1/remote-assist/respond` IPC endpoint.

## 4. Troubleshooting

### Spire Hub says the agent is offline

```bash
sudo systemctl status spired
sudo systemctl enable --now spired
ls -la /run/spire/agent.sock
```

Expected socket mode:

```text
srw-rw-rw- 1 root root ... /run/spire/agent.sock
```

### HTTP 403 from the UNIX socket

Check the active local session:

```bash
loginctl show-seat seat0 -p ActiveSession
loginctl show-session "$(loginctl show-seat seat0 -p ActiveSession --value)" -p User
id -u
```

An SSH user who is not the active `seat0` user is intentionally refused. Root is allowed for local administration.

### Inspect local state

```bash
spire-ctl status
sudo cat /etc/spire/policy-cache.json
sudo cat /etc/spire/pending-reports.json
```

Both cache files are plaintext JSON protected by filesystem permissions; they are not encrypted.

### Trigger a sync

As the active graphical user:

```bash
spire-ctl sync
```

Root can also run a complete one-shot agent cycle:

```bash
sudo /usr/local/bin/spired -config /etc/spire/config.yaml -once
```

### Inspect logs

```bash
sudo journalctl -u spired.service -n 200 --no-pager
sudo journalctl -u spired.service -f
```
