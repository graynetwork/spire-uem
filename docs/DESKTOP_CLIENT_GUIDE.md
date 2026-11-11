# Spire Hub Desktop Client & Field Troubleshooting Guide

This guide covers the operation, user features, and troubleshooting procedures for **Spire Hub** (`org.spire.hub`), the unprivileged GTK4 / Libadwaita client application running on managed corporate Debian and Ubuntu workstations.

---

## 1. Overview & Desktop Integration

**Spire Hub** serves as the user-facing bridge between enterprise security posture and desktop productivity. It allows employees to inspect their machine's compliance status, browse approved enterprise software, and authorize IT support sessions without requiring root or `sudo` credentials.

### Desktop Entry Details
- **Application ID**: `org.spire.hub`
- **Binary Path**: `/usr/bin/spire-hub`
- **Desktop Entry**: `/usr/share/applications/spire-hub.desktop`
- **Icon**: `/usr/share/icons/hicolor/scalable/apps/spire-hub.svg`
- **Categories**: `System;Settings;GTK;`

---

## 2. Key Features for End Users

### 2.1. Machine Security & Health Posture
Upon launching Spire Hub, the **Dashboard** ribbon displays the workstation's real-time security status:
- **Hardware Integrity (TPM 2.0)**: Displays `Attested` (Green checkmark) when UEFI firmware, bootloader, and Secure Boot hashes match corporate baselines.
- **Disk Encryption (LUKS2)**: Indicates that storage volumes are actively encrypted and escrowed.
- **Patch Status**: Displays kernel and OS update readiness, alerting the user when a system reboot is required to finalize critical security updates.
- **Compliance Score**: Shows overall adherence to corporate policies and CIS benchmark standards.

### 2.2. Enterprise Software Portal
Click on the **Applications** tab to access corporate-approved software:
- **Required Applications**: Displayed with a lock icon. These packages (e.g. corporate VPN, security agents) are managed automatically by IT and cannot be uninstalled.
- **Self-Service Applications**: Software made `AVAILABLE` by IT administrators. Users can click **Install** to add tools on demand (e.g., Slack, VS Code, VLC).
- **Zero-Privilege Installation**: The user does not need to enter an administrator password. The install request is submitted across the secure local IPC socket to `spired`, which performs the package installation safely in the background.

### 2.3. Authorizing Attended IT Support
When an IT support technician initiates a remote assistance session from the SpireUEM console:
1. Spire Hub immediately presents a prominent modal dialog on the user's primary monitor.
2. The prompt displays:
   - Requesting Technician Name / Username.
   - Remote IP address and timestamp.
   - Scope of requested access (e.g., Screen View, Diagnostic Shell).
3. The user can click **Authorize Access** to allow the technician to connect, or click **Deny** to reject the request.
4. Sessions terminate immediately when the user clicks **Disconnect** in Spire Hub.

---

## 3. Architecture & Socket Communication

Spire Hub communicates with the local `spired` daemon exclusively through a local UNIX domain socket:

```text
+-----------------------+                    +-----------------------+
|       Spire Hub       |                    |     spired Daemon     |
|   (Unprivileged App)  |                    |    (System Service)   |
|   UID: 1000 (seat0)   |                    |       UID: 0 (root)   |
+-----------+-----------+                    +-----------+-----------+
            |                                            |
            |     Connect /run/spire/agent.sock          |
            +------------------------------------------->|
            |                                            |
            |     Kernel SO_PEERCRED Verification        |
            |     Checks: caller UID == seat0 UID        |
            |<-------------------------------------------+
            |                                            |
            |     IPC Status, Install, Remote Assist     |
            |<==========================================>|
```

### IPC Endpoints on `/run/spire/agent.sock`
- `GET /v1/status`: Returns hardware attestation, reboot flags, and active policy list.
- `GET /v1/catalog`: Returns partitioned list of `REQUIRED` and `AVAILABLE` applications.
- `POST /v1/apps/{id}/install`: Triggers background installation of an approved application.
- `POST /v1/apps/{id}/remove`: Triggers uninstallation of an optional application.
- `POST /v1/remote-assist/respond`: Delivers user approval or denial for remote assistance.

---

## 4. Field Troubleshooting & Diagnostics

### 4.1. Error: "Cannot connect to Spire agent socket"
**Symptoms**: Spire Hub displays an offline warning banner: *"Spire Agent is not running"*.

**Diagnosis & Resolution**:
1. Check if the `spired` background service is running:
   ```bash
   sudo systemctl status spired
   ```
2. If inactive, start and enable the service:
   ```bash
   sudo systemctl enable --now spired
   ```
3. Verify that the UNIX domain socket exists and has correct permissions (`0666`):
   ```bash
   ls -la /run/spire/agent.sock
   # Expected output: srw-rw-rw- 1 root root 0 ... /run/spire/agent.sock
   ```

### 4.2. Error: "HTTP 403 Forbidden: Caller UID != seat0 UID"
**Symptoms**: Spire Hub or `spire-ctl` fails to communicate with the socket, returning an authorization error in `/var/log/syslog` or systemd journal.

**Diagnosis & Resolution**:
The `spired` IPC layer uses `SO_PEERCRED` to restrict socket access to the active physical console user on `seat0`:
1. Check the active console seat user registered by systemd logind:
   ```bash
   loginctl show-seat seat0 -p ActiveSession
   loginctl show-session $(loginctl show-seat seat0 -p ActiveSession --value) -p User
   ```
2. If running under SSH or a secondary terminal multiplexer, Spire Hub must be executed within the graphical session environment:
   ```bash
   # Verify current user matches the logged in desktop user (UID 1000)
   id -u
   ```

### 4.3. Inspecting Local Policy Cache
If the workstation is disconnected from the corporate network, `spired` operates from its local policy cache. You can inspect the active policy set via `spire-ctl`:
```bash
spire-ctl status
```
Or inspect the encrypted cache file directly (requires root):
```bash
sudo cat /etc/spire/policy-cache.json
```

### 4.4. Forcing an Immediate Fleet Resynchronization
To immediately fetch newly assigned policies or applications without waiting for the scheduled check-in interval:
```bash
sudo spire-ctl sync
```
Or execute a one-shot execution run:
```bash
sudo /usr/local/bin/spired -config /etc/spire/config.yaml -once
```
