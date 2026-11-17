# SpireUEM Bare-Metal Hardware Qualification & Operational Runbook

**Document ID:** `SPIRE-OPS-BM-001`  
**Target Operating System:** Debian 12 (Bookworm) `amd64`  
**Validation Harness:** [`scripts/test_baremetal.sh`](../scripts/test_baremetal.sh)

---

## 1. Target Hardware Profile

Physical qualification must be executed on production-representative enterprise x86_64 workstations meeting the following baseline specifications:

| Subsystem | Minimum Qualification Spec | Recommended Enterprise Spec (Pilot Fleet) |
| :--- | :--- | :--- |
| **System Architecture** | x86_64 (Intel Core 11th Gen+ / AMD Ryzen 5000 Pro+) | Lenovo ThinkPad T14s / P1 Gen 6, Dell Latitude 7440, HP EliteBook 840 G10 |
| **System Firmware** | UEFI 2.7+ Class 3 (No CSM / Legacy BIOS) | UEFI 2.8+ with LVFS (`fwupd`) capsule update support |
| **Hardware Root of Trust** | Firmware TPM 2.0 (Intel PTT / AMD fTPM) | Discrete TPM 2.0 (`dTPM`, TCG 2.0 rev 1.38+, FIPS 140-2/3 certified, e.g., Infineon SLB9670 / Nuvoton NPCT75x) |
| **Primary Storage** | 256 GB NVMe M.2 SSD (`/dev/nvme0n1`) | 512 GB+ NVMe PCIe Gen4 SSD (Non-OPAL software LUKS2 encryption) |
| **Memory (RAM)** | 8 GB LPDDR4x/DDR4 (for Argon2id KDF + OpenSCAP XCCDF evaluation) | 16 GB – 32 GB LPDDR5/DDR5 |
| **Display & Session** | Integrated GPU supporting Wayland (`seat0`) | Intel Iris Xe / AMD Radeon 780M running GNOME 43 (Wayland session) |

---

## 2. BIOS / UEFI Firmware Settings Matrix

Before booting the Debian 12 installer, enter the system UEFI Setup utility (`F1` / `F2` / `F10`) and enforce the following hardware security configuration:

| UEFI Setting Category | Parameter Name | Required State | Security & Attestation Rationale |
| :--- | :--- | :--- | :--- |
| **Boot Mode** | UEFI / Legacy Boot | **UEFI Only (CSM Disabled)** | Required for UEFI Secure Boot measurements into SHA-256 PCR 7. |
| **Secure Boot** | Secure Boot Status | **Enabled (Standard / Deployed Mode)** | Ensures `shimx64.efi` -> `grubx64.efi` -> signed Debian kernel chain is measured into PCR 7 (`SecureBoot-*` efivar = `1`). |
| **Secure Boot Keys** | Factory Default Keys | **Microsoft + Vendor CA Active** | Required to validate Debian's Microsoft-signed `shim-signed` first-stage bootloader. |
| **Security Chip / TPM** | Security Chip 2.0 / Intel PTT / AMD fTPM | **Enabled & Active** | Exposes `/dev/tpm0` and kernel resource manager `/dev/tpmrm0` to `spired`. |
| **TPM Hierarchy** | Endorsement, Storage & Platform Hierarchies | **Enabled** | Required for `spired` to read the manufacturer EK certificate and provision the Attestation Key (AK). |
| **TPM Clear** | Clear Security Chip | **Execute Once Prior to OS Install** | Resets stale Owner/Lockout authorization values from prior OS installations. |
| **Boot Optimization** | Fast Boot / Quick Boot | **Disabled (Thorough)** | Ensures full pre-boot bus enumeration and consistent PCR 0/2/4 measurements across cold boots. |
| **DMA Protection** | Kernel DMA Protection / VT-d / IOMMU | **Enabled** | Prevents Thunderbolt/PCIe physical DMA attacks against in-memory LUKS2 master keys. |
| **BIOS Access** | Supervisor / Admin Password | **Set (Escrowed in IT Vault)** | Prevents unprivileged users from disabling Secure Boot or clearing the TPM. |

---

## 3. Clean Debian 12 (Bookworm) Installation Recipe

### 3.1 Installation Media & Boot
1. Download the official **Debian 12 (Bookworm) `amd64` netinst ISO** (`debian-12.x.0-amd64-netinst.iso`) and verify its `SHA512SUMS.sign` GPG signature.
2. Write the ISO to a USB flash drive (`dd if=debian-12.x.0-amd64-netinst.iso of=/dev/sdX bs=4M status=progress oflag=sync`).
3. Boot the workstation in **UEFI Mode** with Secure Boot **Enabled**.

### 3.2 Partitioning & LUKS2 Full-Disk Encryption Layout
In the Debian Installer **Partition disks** stage, select **Guided - use entire disk and set up encrypted LVM** (or configure manually to match the partition table below on `/dev/nvme0n1`):

| Partition | Mount Point / Role | Filesystem / Type | Size | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `/dev/nvme0n1p1` | `/boot/efi` | EFI System Partition (`FAT32`) | `512 MB` | Contains signed `shimx64.efi` and `grubx64.efi`. |
| `/dev/nvme0n1p2` | `/boot` | `ext4` (Unencrypted) | `1024 MB` | Contains signed kernel `vmlinuz-6.1.0-*-amd64` and `initrd.img`. |
| `/dev/nvme0n1p3` | Physical Volume for Encryption | `crypto_LUKS` (**LUKS2**, AES-XTS-PLAIN64, 512-bit key, Argon2id) | Remaining Disk | Unlocked as `/dev/mapper/nvme0n1p3_crypt` via Keyslot 0 (user passphrase). |
| `vg0-root` | `/` | `ext4` (on LVM inside LUKS2) | `90%+ VG` | Encrypted root filesystem. |
| `vg0-swap` | `swap` | `swap` (on LVM inside LUKS2) | `8 GB` | Encrypted swap volume. |

### 3.3 Software Selection (`tasksel`)
Select the following tasks during installation:
- `[x] Debian desktop environment`
- `[x] ... GNOME`
- `[x] SSH server` (optional, for remote lab orchestration)
- `[x] standard system utilities`

### 3.4 Post-Install Prerequisite Packages
Once booted into Debian 12, ensure hardware attestation and OpenSCAP packages are installed (the SpireUEM `.deb` package declares these dependencies automatically):
```bash
sudo apt-get update
sudo apt-get install -y \
    curl gpg ca-certificates cryptsetup-bin tpm2-tools mokutil \
    liboscap8 ssg-base ssg-debderived flatpak python3-gi gir1.2-gtk-4.0 gir1.2-adw-1
```

---

## 4. Step-by-Step Qualification Procedure

### 4.1 Endpoint onboarding
Set the public server base URL first, then download and inspect the bootstrap before running it:
```bash
curl -fsSLo /tmp/spire-install.sh https://spire.example.com/install.sh
less /tmp/spire-install.sh
sudo bash /tmp/spire-install.sh --server-url https://spire.example.com
```

For an isolated lab using plain HTTP, the server must set `SPIRE_ALLOW_INSECURE_HTTP=1`, and the bootstrap must be run with `--allow-insecure-http`:

```bash
curl -fsSLo /tmp/spire-install.sh http://<SPIRE_SERVER_IP>:8080/install.sh
sudo bash /tmp/spire-install.sh --server-url http://<SPIRE_SERVER_IP>:8080 --allow-insecure-http
```

Approve the newly staged device in **Devices → Approve**. The standard bootstrap uses administrator approval; it does not consume dynamic `spire_tok_...` enrollment tokens.

---

### 4.2 Running the Automated Bare-Metal Qualification Suite
Execute [`scripts/test_baremetal.sh`](../scripts/test_baremetal.sh) as `root`:

```bash
# 1. Safe Dry-Run (validates pre-flight checks without mutating kernel/LUKS/Flatpak state):
sudo ./scripts/test_baremetal.sh --dry-run --verbose

# 2. Full Hardware Qualification Run (skipping interactive cold-reboot prompt):
sudo ./scripts/test_baremetal.sh \
    --server-url "https://spire.example.com" \
    --admin-user "admin" \
    --admin-pass "spire-admin-secret" \
    --skip-reboot \
    --verbose
```

---

### 4.3 Phase-by-Phase Manual Verification Reference

#### Pre-Flight & Phase 1: TPM 2.0, Secure Boot & LUKS2 Header Inspection
1. **Verify TPM 2.0 Character Device & Fixed Properties:**
   ```bash
   ls -la /dev/tpmrm0
   sudo tpm2_getcap properties-fixed | grep -E "TPM2_PT_FAMILY_INDICATOR|TPM2_PT_MANUFACTURER" -A 2
   ```
   *Expected Output:*
   ```text
   crw-rw---- 1 tss tss 253, 65536 Nov 08 08:30 /dev/tpmrm0
   TPM2_PT_FAMILY_INDICATOR:
     raw: 0x322E3000
     value: "2.0"
   ```

2. **Verify UEFI Secure Boot State:**
   ```bash
   mokutil --sb-state
   od -An -t u1 /sys/firmware/efi/efivars/SecureBoot-*
   ```
   *Expected Output:* `SecureBoot enabled` and trailing byte `1`.

3. **Verify SHA-256 PCR Banks 0, 2, 4, and 7:**
   ```bash
   sudo tpm2_pcrread sha256:0,2,4,7
   ```
   *Expected Output:* Non-zero 64-character hex digests across all four PCR indices.

---

#### Phase 2: Deb822 APT Repository & Dynamic TPM 2.0 Attestation
1. **Verify Deb822 Repository & GPG Keyring:**
   ```bash
   cat /etc/apt/sources.list.d/spire.sources
   gpg --show-keys /etc/apt/keyrings/spire.gpg
   ```
2. **Inspect `spired` Systemd Journal for Attestation Handshake:**
   ```bash
   sudo journalctl -u spired -n 100 --no-pager | grep -iE "TPM|attest"
   ```
   *Expected Output:*
   ```text
   [spired] TPM 2.0 attestation completed status=ATTESTED secure_boot=true
   ```
3. **Approve the qualified measurements as a PCR baseline (fleet onboarding):**
   Once a representative, fully-updated reference unit of this hardware/firmware class reads
   `ATTESTED`, approve its quote-proven PCR values as an approved baseline so sibling devices
   are checked against a known-good set: in the admin UI open the device → attestation panel →
   **Approve current measurements**, scoping the baseline to this hardware class's tags (and
   ring, if used). Thereafter a matching unit reads `BASELINE_MATCH`; a unit whose boot chain
   drifts reads `BASELINE_MISMATCH` with the differing PCR indices. See
   `ADMIN_RUNBOOK.md` §15 for re-approving after a firmware/bootloader update and for the
   `off → warn → enforce` secret-gating rollout. The required PCR set is exactly the SHA-256
   bank 0, 2, 4, 7 verified in Phase 1.

---

#### Phase 3: LUKS2 Keyslot 1 Escrow & Break-Glass Recovery Verification
1. **Verify LUKS2 Keyslot 1 Allocation on Backing Device:**
   ```bash
   sudo cryptsetup luksDump /dev/nvme0n1p3 | sed -n '/^Keyslots:/,/^Tokens:/p'
   ```
   *Expected Output:*
   - Keyslot `0: luks2` (Primary user install passphrase)
   - Keyslot `1: luks2` (SpireUEM autonomous recovery key with `argon2id` or `pbkdf2` KDF)

2. **Execute Break-Glass Recovery Key Reveal (`HW-PILOT-001`):**
   ```bash
   curl -fsSL -u "admin:spire-admin-secret" \
     -H "Content-Type: application/json" \
     -H "Accept: application/json" \
     -X POST "https://spire.example.com/api/v1/auth/recovery-key" \
     -d '{"device_id":"<DEVICE_UUID>","volume_uuid":"<LUKS_UUID>","reason":"HW-PILOT-001"}'
   ```
   *Expected Output:* JSON containing a 48-character `recovery_key`, plus an immutable `LUKS_KEY_REVEAL` event in `GET /admin/audit/events`. The reveal also queues recovery-key rotation.

3. **Cold-Boot Unlock Verification (When `--skip-reboot` is omitted):**
   Reboot the physical workstation (`sudo reboot`). At the `cryptsetup` initramfs prompt, enter the revealed 48-character recovery key instead of the user's primary passphrase and confirm the workstation boots into GDM/GNOME.

---

#### Phase 4: Live OpenSCAP CIS Evaluation & Kernel Drift Self-Healing
1. **Trigger CIS Scan & Induce Kernel Drift:**
   ```bash
   sudo sysctl -w net.ipv4.conf.all.rp_filter=0
   cat /proc/sys/net/ipv4/conf/all/rp_filter   # Outputs: 0
   ```
2. **Apply One-Click CIS Rule Remediation & Sync:**
   ```bash
   curl -fsSL -u "admin:spire-admin-secret" \
     -H "Content-Type: application/json" \
     -X POST "https://spire.example.com/admin/benchmarks/remediate-rule" \
     -d '{"rule_id":"xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_rp_filter"}'
   sudo spire-ctl sync
   cat /proc/sys/net/ipv4/conf/all/rp_filter   # Outputs: 1
   ```

---

#### Phase 5: Unprivileged `seat0` Desktop IPC & Spire Hub (`org.spire.hub`)
1. **Verify Active `seat0` Graphical Session:**
   ```bash
   loginctl list-sessions
   ```
2. **Test Unprivileged `SO_PEERCRED` IPC Socket as Console User:**
   ```bash
   curl -fsSL --unix-socket /run/spire/agent.sock http://localhost/v1/status
   curl -fsSL --unix-socket /run/spire/agent.sock http://localhost/v1/catalog
   ```
3. **Launch Spire Hub GUI:**
   Open **Activities -> Spire Hub** (or run `/usr/bin/spire-hub` from a desktop terminal) and install a curated Flatpak application (e.g., `org.videolan.VLC`), then confirm installation via `flatpak list --app`.

---

## 5. Field Troubleshooting Matrix

### Scenario 1: TPM 2.0 Dictionary Attack (DA) NVRAM Lockout (`TPM_RC_LOCKOUT` / `0x921`)
- **Symptom:** `journalctl -u spired` or `tpm2_quote` fails with `TPM_RC_LOCKOUT (0x921)` after repeated failed authorization attempts during lab testing.
- **Resolution:**
  Clear the TPM dictionary attack lockout counter using the lockout hierarchy:
  ```bash
  sudo tpm2_dictionarylockout --clear-lockout
  sudo systemctl restart spired
  ```
  If the lockout hierarchy auth value is unknown, reboot into UEFI Setup and execute **Security -> TPM 2.0 -> Clear Security Chip**.

### Scenario 2: PCR 7 Value Changes After Kernel, GRUB, or `shim-signed` Update (`dbx` / MOK Update)
- **Symptom:** After an `unattended-upgrades` update of `shim-signed`, `grub-efi-amd64-signed`, or UEFI `fwupd` `dbx` revocation lists, PCR 0/4/7 digests change on reboot.
- **Resolution:**
  1. Verify UEFI Secure Boot remains enabled (`mokutil --sb-state` -> `SecureBoot enabled`).
  2. Trigger a fresh attestation cycle via `sudo spire-ctl sync`.
  3. `spired` performs a fresh challenge-response quote (`POST /api/v1/desktop/attest/challenge` → `POST /api/v1/desktop/attest/verify`). The server verifies the EK/AK binding, nonce, signature, and signed PCR digest, then stores the latest values in `device_tpm_attestation`.
  4. SpireUEM does **not** compare the new PCR values with an approved baseline. A changed-but-valid PCR set can still be `ATTESTED` if PCR 7 is nonzero. Investigate the change through firmware, bootloader, and Secure Boot tooling; do not treat `ATTESTED` as proof that measurements match the previous boot.

### Scenario 3: LUKS2 Keyslot 1 is already occupied
- **Symptom:** escrow fails because the current implementation always requests Keyslot 1 and `cryptsetup luksAddKey --key-slot 1` refuses to replace an occupied slot.
- **Behavior:** `spired` fails closed. It does not run `luksKillSlot`, does not overwrite the existing key, and does not create `/etc/spire/luks-keyslot1.key`.
- **Resolution:**
  1. Confirm another working key opens the volume and back up the LUKS header.
  2. Determine who owns Keyslot 1 and whether it can be retired under your recovery-key procedure.
  3. If retiring it is approved, remove it manually with `cryptsetup` while preserving at least one tested working key.
  4. Ensure `/etc/spire/luks-master.key` contains a valid provisioning key with mode `0400`, then run `sudo spire-ctl sync`.
  5. Verify the new escrowed recovery key before removing the provisioning keyfile.

Do not automate deletion of an occupied keyslot based only on this runbook. The product currently has no configurable escrow-slot selector.

### Scenario 4: `HTTP 403 Caller is not the active console session user` on `/run/spire/agent.sock`
- **Symptom:** Running `spire-ctl` or `spire-hub` returns HTTP 403 over `/run/spire/agent.sock`.
- **Root Cause:** The caller is executing from an SSH session or background service account whose UID does not match the active graphical console user on `seat0`.
- **Resolution:**
  1. Ensure a user is logged into the local GDM3 / GNOME desktop (`loginctl show-seat seat0 -p ActiveSession`).
  2. For headless CLI administration over SSH, invoke `sudo spire-ctl status` (UID 0 is unconditionally authorized by the `SO_PEERCRED` middleware).
