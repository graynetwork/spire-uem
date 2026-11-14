# SpireUEM v0.1.0 — Production Operations & Administrator Runbook

SpireUEM is an outbound-only Unified Endpoint Management (UEM) platform engineered for Debian 12+ (`bookworm` / `trixie`) desktop and kiosk fleets. This runbook documents bare-metal server deployment, database disaster recovery, firewall configuration, single-command endpoint onboarding, and field troubleshooting.

---

## 1. Architecture Overview

| Component | Binary / Artifact | Role |
| :--- | :--- | :--- |
| **Control Plane (`spire-server`)** | `bin/spire-server` | Serves the HTMX/Tailwind Admin Console (`/admin/*`), public onboarding installer (`/install.sh`, `/dist/*.deb`), and Desktop Agent REST API (`/api/v1/desktop/*`). |
| **Endpoint Agent (`spired`)** | `dist/spire-agent_0.1.0_amd64.deb` | Root daemon running on managed Debian endpoints (`spired.service`). Polls the control plane, enforces `apt`/`dconf`/`systemd` policies, reconciles configuration drift offline via `/etc/spire/policy-cache.json`, and executes queued diagnostic commands. |
| **State Store** | PostgreSQL 15+ | Stores device inventory, SHA-256 hashed bearer tokens, tag-targeted declarative policies, compliance audit history, and diagnostic command outputs. |

---

## 2. Server Deployment (`systemd` & PostgreSQL 15+)

### 2.1 Build Release Artifacts
From the repository root on your build host:
```bash
make release
cat dist/checksums.txt
```
This produces:
- `bin/spire-server` (`dist/spire-server_0.1.0_linux_amd64`)
- `bin/spired` (`dist/spired_0.1.0_linux_amd64`)
- `dist/spire-agent_0.1.0_amd64.deb`
- `dist/checksums.txt`

### 2.2 Provision PostgreSQL 15+ Database
```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE spire WITH LOGIN PASSWORD 'CHANGE_ME_STRONG_DB_PASSWORD';
CREATE DATABASE spire_uem OWNER spire;
GRANT ALL PRIVILEGES ON DATABASE spire_uem TO spire;
SQL
```
> **Note:** `spire-server` automatically runs all SQL migrations in `/opt/spire-uem/migrations/*.up.sql` on startup.

### 2.3 Install `spire-server` as a `systemd` Service
1. Copy the server binary, migrations, packaging script, and `.deb` distribution directory to `/opt/spire-uem`:
   ```bash
   sudo mkdir -p /opt/spire-uem/bin /opt/spire-uem/dist /opt/spire-uem/migrations /opt/spire-uem/packaging
   sudo cp bin/spire-server /opt/spire-uem/bin/spire-server
   sudo cp -r migrations/* /opt/spire-uem/migrations/
   sudo cp packaging/bootstrap.sh /opt/spire-uem/packaging/bootstrap.sh
   sudo cp dist/spire-agent_0.1.0_amd64.deb /opt/spire-uem/dist/
   sudo chmod 0755 /opt/spire-uem/bin/spire-server
   ```

2. Create the environment configuration file at `/etc/spire-server.env` (mode `0600`):
   ```bash
   sudo tee /etc/spire-server.env >/dev/null <<'EOF'
   SPIRE_SERVER_LISTEN_ADDR=:8080
   SPIRE_DB_DSN=postgres://spire:CHANGE_ME_STRONG_DB_PASSWORD@127.0.0.1:5432/spire_uem?sslmode=disable
   SPIRE_ADMIN_USER=admin
   SPIRE_ADMIN_PASSWORD=CHANGE_ME_STRONG_ADMIN_PASSWORD
   # PEM bundle of TPM manufacturer CA certificates (roots + intermediates).
   # Without it, hardware TPM attestations are reported FAILED.
   SPIRE_TPM_EK_ROOTS=/etc/spire/tpm-ca-bundle.pem
   # At least 32 random characters, e.g. `openssl rand -hex 32`. Keeps admins signed in across restarts.
   SPIRE_SESSION_SECRET=CHANGE_ME_64_HEX_CHARS
   # Only behind a TLS-terminating reverse proxy that clients cannot bypass:
   # SPIRE_TRUST_PROXY=true
   EOF
   sudo chmod 0600 /etc/spire-server.env
   ```

   Security-relevant settings:

   | Variable | Effect |
   |---|---|
   | `SPIRE_ADMIN_PASSWORD` | Enables the static break-glass account `SPIRE_ADMIN_USER`. Must be at least 12 characters and not a known default. Unset = break-glass disabled. On first start it also replaces the seeded `changeme` password of the `admin` account; the server refuses to start while any active local account still uses `changeme`. |
   | `SPIRE_TPM_EK_ROOTS` | TPM manufacturer CA bundle used to verify EK certificates. Required for hardware attestation to succeed. |
   | `SPIRE_SIMULATE_TPM2` / `SPIRE_ALLOW_SIMULATED_TPM` | Accept software-simulated TPM attestations. **Test environments only**: a simulated attestation proves nothing about the device. |
   | `SPIRE_ENABLE_TEST_ENDPOINTS` | Registers the unauthenticated `/auth/oidc/test-callback` used by the E2E suite. **Never set in production**: it lets any caller mint an admin session. |
   | `SPIRE_SESSION_SECRET` | Key that signs admin session cookies. If unset (or under 32 characters) a random key is generated per process and every restart signs all admins out. |
   | `SPIRE_TRUST_PROXY` | Trust `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-Proto` from a reverse proxy. Set it only when clients cannot reach the server except through that proxy; otherwise they can spoof their IP in audit logs. Required when `enforce_https` is on, since the server itself speaks plain HTTP: it refuses to start with `enforce_https` and no trusted proxy. |
   | `general.server_base_url` (Settings → General) | The server's public URL. Used for the OIDC redirect URI and written into `/install.sh`. Until it is changed from the seeded `http://localhost:8080`, `/install.sh` uses the request's Host header instead (validated as a plain host name). Set it before onboarding devices. |

   **Sessions** are recorded server-side. Logging out ends the session, and disabling an account or changing its password or role ends all of that account's sessions immediately.

   **Roles.** `OPERATOR` and above can run arbitrary shell commands as root (`/bin/sh -c`) and open root terminals on every enrolled device. Treat those roles as root on the whole fleet: grant them only to people you would give root on every endpoint, and use `AUDITOR` for read-only access.

3. Create `/etc/systemd/system/spire-server.service`:
   ```ini
   [Unit]
   Description=SpireUEM Control Plane Server
   After=network-online.target postgresql.service
   Wants=network-online.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/opt/spire-uem
   EnvironmentFile=/etc/spire-server.env
   ExecStart=/opt/spire-uem/bin/spire-server
   Restart=always
   RestartSec=5
   StandardOutput=journal
   StandardError=journal

   [Install]
   WantedBy=multi-user.target
   ```

4. Enable and start `spire-server`:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now spire-server.service
   sudo systemctl status spire-server.service
   ```

---

## 3. PostgreSQL Backup & Restore Procedures

### 3.1 Automated / Ad-Hoc Backup (`pg_dump`)
Run a compressed custom-format dump (`-Fc`) to capture all device inventory, token hashes, policies, compliance records, and command logs:
```bash
BACKUP_FILE="/var/backups/spire-uem-$(date -u +%Y%m%d-%H%M%S).dump"
PGPASSWORD="CHANGE_ME_STRONG_DB_PASSWORD" pg_dump \
  -h 127.0.0.1 -p 5432 -U spire -d spire_uem \
  -Fc -f "${BACKUP_FILE}"
sha256sum "${BACKUP_FILE}" > "${BACKUP_FILE}.sha256"
```

### 3.2 Database Restore (`pg_restore`)
1. Stop `spire-server` to prevent concurrent writes:
   ```bash
   sudo systemctl stop spire-server.service
   ```
2. Restore the snapshot cleanly into `spire_uem`:
   ```bash
   PGPASSWORD="CHANGE_ME_STRONG_DB_PASSWORD" pg_restore \
     -h 127.0.0.1 -p 5432 -U spire -d spire_uem \
     --clean --if-exists "${BACKUP_FILE}"
   ```
3. Restart `spire-server`:
   ```bash
   sudo systemctl start spire-server.service
   ```

---

## 4. Host Firewall & Network Rules

SpireUEM requires **zero inbound ports** on managed Debian desktop endpoints. All communication is initiated outbound by `spired` to `spire-server`.

### 4.1 Control Plane Firewall (`ufw`)
Allow inbound TCP port `8080` (direct) or `80`/`443` (when fronted by Caddy/Nginx TLS reverse proxy) from your management and endpoint subnets:
```bash
# Direct HTTP/8080 access on LAN
sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp comment "SpireUEM Control Plane"

# Or if using a TLS Reverse Proxy (Nginx / Caddy)
sudo ufw allow 80/tcp comment "SpireUEM HTTP Redirect"
sudo ufw allow 443/tcp comment "SpireUEM HTTPS Ingress"
sudo ufw reload
```

---

## 5. Bare-Metal Endpoint Onboarding Flow

### Step 1: Run Single-Command Bootstrap on the Target Debian Machine
On any physical or virtual Debian 12/13 (`amd64`) machine with network reachability to `spire-server`:
```bash
curl -sSL http://<server-ip>:8080/install.sh | sudo bash
```
What this command performs automatically:
1. Verifies root privileges (`EUID == 0`) and `amd64` architecture.
2. Downloads `/dist/spire-agent_0.1.0_amd64.deb` from `spire-server`.
3. Installs the package via `dpkg -i` (`/usr/local/bin/spired` and `/lib/systemd/system/spired.service`).
4. Writes `/etc/spire/config.yaml` (mode `0600`) pointing to `http://<server-ip>:8080`.
5. Reloads `systemd`, enables `spired.service`, and starts the daemon immediately.

### Step 2: Tag & Approve Endpoint in the Admin Web UI
1. Open `http://<server-ip>:8080/admin/devices` and authenticate with `SPIRE_ADMIN_USER` / `SPIRE_ADMIN_PASSWORD`.
2. Locate the newly staged endpoint (`status = PENDING_APPROVAL`).
3. Assign optional fleet tags (e.g., `laptop`, `kiosk`, `engineering`) and click **Save**.
4. Click **Approve**.
5. On its next poll cycle (default `5s`), `spired` claims its single-use bearer token (the server releases it only to the agent holding the enrollment key that first staged the device, see below), persists it to `/etc/spire/agent.token` (mode `0600`), caches its active policy set to `/etc/spire/policy-cache.json`, and enforces all assigned policies.

### Enrollment keys and re-installing an agent
On first start `spired` generates a random enrollment key and stores it in `/etc/spire/enrollment.key` (mode `0600`), next to the token. The server binds the device record to that key when the device is first staged, and refuses any later enroll request for the same hardware UUID that presents a different key. Knowing a machine's hardware UUID is therefore not enough to collect its token.

If you reinstall the OS or delete `/etc/spire/`, the new agent has a new key and is refused with `enrollment key mismatch`. **Revoke** the device in the Admin UI: revoking releases the key binding, the new agent stages the device again on its next poll, and you approve it as normal.

---

## 6. Operational Troubleshooting & Verification

### 6.1 Inspect Live Client Agent Logs (`journalctl`)
```bash
sudo journalctl -u spired.service -f
```
Key log markers:
- `[spired] device approved! Token persisted to /etc/spire/agent.token (mode 0600)` — Enrollment completed.
- `[WARN] Server unreachable; falling back to local policy cache` — Agent is operating in offline resilience mode and enforcing cached policies.
- `[spired] flushed N buffered offline reports` — Agent reconnected to `spire-server` and uploaded buffered offline compliance reports.

### 6.2 Inspect Local Offline Policy Cache & Pending Report Buffer
Verify what policies the endpoint has cached locally for offline drift remediation:
```bash
sudo cat /etc/spire/policy-cache.json
```
Check if any offline compliance reports are buffered awaiting server connectivity:
```bash
sudo cat /etc/spire/pending-reports.json
```

### 6.3 Trigger an Immediate Single Enforcement Cycle
To force a synchronous check-in or offline reconciliation pass without waiting for the timer:
```bash
sudo /usr/local/bin/spired -config /etc/spire/config.yaml -once
```

### 6.4 Verify `dconf` System Locks & Compiled Database
1. Inspect the isolated per-policy keyfiles and lock files managed by `spired`:
   ```bash
   ls -la /etc/dconf/db/local.d/
   ls -la /etc/dconf/db/local.d/locks/
   cat /etc/dconf/profile/user
   ```
2. Dump the compiled binary `dconf` database or verify lock enforcement:
   ```bash
   dconf dump /
   ```

### 6.5 Export Fleet Compliance Audit Reports (CSV / JSON)
Administrators and auditors can export a complete compliance snapshot via the **Export Audit** buttons on `/admin/devices` or via CLI:
```bash
# Export CSV Audit Report
curl -sSL -u "admin:${SPIRE_ADMIN_PASSWORD}" "http://<server-ip>:8080/admin/compliance/export?format=csv" -o compliance-audit.csv

# Export JSON Audit Report
curl -sSL -u "admin:${SPIRE_ADMIN_PASSWORD}" "http://<server-ip>:8080/admin/compliance/export?format=json" -o compliance-audit.json
```

## 7. Lost-Device Actions (Lock / Mark Lost / Crypto-Erase Wipe / Recovery-Key Rotation)

All four actions are driven from the device detail page on `/admin/devices` and are delivered
to the endpoint either by a live gateway push (when connected) or as a queued directive on the
agent's next check-in. Each action is audited via `system_audit_events` and reports a status
(queued / delivered / done / failed) back onto the device page.

### 7.1 Lock Sessions — role: OPERATOR+
Immediately locks all graphical sessions on the endpoint (`loginctl lock-sessions`). An optional
message is shown to the signed-in user via `notify-send` when a desktop session is present.
Fire-and-forget; one directive per click.

### 7.2 Mark Lost / Clear Lost — role: SECURITY_ADMIN+
Marking a device **LOST** sets a new `devices.is_lost` flag (it does NOT replace the device
`status`) and records a directive the agent applies on its next contact:
- locks all graphical sessions;
- writes `/etc/nologin` with an operator message, blocking new local logins (root console is
  unaffected — this is deliberately safer than `passwd -l`) and expires non-root sessions;
- increases its own check-in frequency;
- reports the facts it already has — the server-observed source IP (`devices.last_seen_ip`) and
  the last active user (`devices.last_active_user`, from the agent's reported active session).

**Clear Lost** reverts only what the agent changed (removes the SpireUEM-owned `/etc/nologin`
via its marker file — a foreign `/etc/nologin` placed by an operator is never removed). The
directive is re-emitted every check-in until the agent acknowledges it via
`POST /api/v1/desktop/actions/report`.

### 7.3 Crypto-Erase Wipe (IRREVERSIBLE) — role: SUPER_ADMIN, two-person rule
Destroys the LUKS keyslots of the device's escrowed encrypted volumes (`cryptsetup luksErase`),
rendering data unrecoverable, then powers the device off. Controls:
- **Typed confirmation**: the requesting admin must type the device hostname exactly.
- **Two-person rule**: a *different* SUPER_ADMIN must approve within 24h. The static break-glass
  `SPIRE_ADMIN_USER` account counts as **one** person, so it cannot both request and approve.
- **Signed order**: on approval the server signs an Ed25519 wipe order over the device's
  escrowed volume UUIDs. The agent pins the server's Ed25519 **public** key at enrollment
  (delivered once in the enroll/check-in response, persisted next to its token) and refuses any
  unsigned, mis-signed, expired, or wrong-device order.
- **Cancellation window**: a request stays cancellable (`PENDING_APPROVAL` or `APPROVED`) until
  the agent actually fetches the order on check-in, at which point it atomically moves to
  `DELIVERED` and can no longer be cancelled.
- **Volume safety**: the agent erases ONLY the intersection of the volumes named in the signed
  order and the volumes it itself reported as escrowed — never its own guess.
- **Lab guard**: set `SPIRE_AGENT_DISABLE_WIPE=1` in the agent's environment to hard-refuse any
  crypto-erase on that endpoint even for a fully valid signed order. Recommended for lab/test
  devices.

Operator steps: Request Wipe (type hostname + reason) → a second SUPER_ADMIN opens the device
page and clicks Approve → the order is delivered on the agent's next check-in → the device
crypto-erases and powers off, reporting `COMPLETED`/`FAILED`.

### 7.4 LUKS Recovery-Key Rotation (automatic after a reveal)
When an admin reveals a LUKS recovery key (`/admin/devices/{id}/luks/reveal`), a rotation is
**automatically queued** for that volume (status `PENDING`). On its next contact the agent:
adds a fresh random recovery key to a free keyslot using its provisioning master keyfile
(`/etc/spire/luks-master.key`), verifies the new key opens the volume
(`cryptsetup open --test-passphrase`), escrows the new key with the existing RSA-OAEP +
AES-256-GCM envelope, then removes the revealed key's slot. The device page shows
`rotation pending / done / failed`.

### 7.5 Server environment / settings
| Variable | Default | Purpose |
| --- | --- | --- |
| `SPIRE_WIPE_SIGNING_KEY_PATH` | `internal/crypto/wipe-signing.pem` | Path to the server's Ed25519 wipe-signing private key (PKCS#8 PEM, mode 0600). Auto-generated on first boot if absent; the public half is what agents pin. Keep it secret and backed up — losing it means outstanding signed orders can no longer be re-issued. |
| `SPIRE_AGENT_DISABLE_WIPE` | _(unset)_ | **Agent-side.** Set to `1` to make the endpoint refuse all crypto-erase wipes. |

### 7.6 Limits
- Wipe depends on the agent having escrowed at least one LUKS volume; a device with no escrow
  cannot be wiped (the request is refused at creation).
- LUKS rotation requires the provisioning master keyfile to be present on the endpoint; if it is
  absent the rotation reports `FAILED` and the revealed key's slot is left intact.
- `/etc/nologin` blocks local logins only; it does not terminate an already-authenticated SSH
  session (non-root graphical sessions are expired, SSH is not).
