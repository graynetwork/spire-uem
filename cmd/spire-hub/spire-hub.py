#!/usr/bin/env python3
"""
SpireUEM Graphical Desktop Client (spire-hub)
Native GTK4 + Libadwaita-1 desktop client communicating over /run/spire/agent.sock.
Strictly separates Security Compliance (System & Security Baseline + Mandatory Applications)
from the non-evaluative Self-Service App Catalog.
"""

import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

DEFAULT_SOCKET_PATH = os.environ.get("SPIRE_SOCKET_PATH", "/run/spire/agent.sock")
APP_ID = "org.spire.hub"


class UnixHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection subclass that dials a local AF_UNIX domain socket."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH, timeout: float = 30.0):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


class SpireIPCClient:
    """Client wrapper for spired's local Unix domain socket IPC server."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH):
        self.socket_path = socket_path

    def _request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        timeout: float = 30.0,
    ) -> dict:
        conn = UnixHTTPConnection(self.socket_path, timeout=timeout)
        try:
            headers = {"Accept": "application/json"}
            payload = None
            if body is not None:
                payload = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw) if raw.strip() else {}
            if resp.status >= 400:
                err_msg = data.get("error", f"HTTP {resp.status}")
                raise RuntimeError(err_msg)
            return data
        finally:
            conn.close()

    def get_status(self) -> dict:
        return self._request("GET", "/v1/status")

    def trigger_sync(self) -> dict:
        return self._request("POST", "/v1/sync")

    def get_catalog(self) -> list[dict]:
        res = self._request("GET", "/v1/catalog")
        return res.get("catalog") or []

    def install_policy(self, policy_id: str) -> dict:
        return self._request("POST", "/v1/install", {"policy_id": policy_id}, timeout=900.0)

    def uninstall_policy(self, policy_id: str) -> dict:
        return self._request("POST", "/v1/uninstall", {"policy_id": policy_id}, timeout=900.0)

    def defer_campaign(self, campaign_id: str) -> dict:
        return self._request("POST", "/v1/campaign/defer", {"campaign_id": campaign_id})

    def browser_cert_config(self) -> dict:
        return self._request("GET", "/v1/browser-cert/config")

    def browser_cert_issue(self, csr_pem: str) -> dict:
        # Only the CSR is sent. spired takes the account name from this process's uid.
        return self._request("POST", "/v1/browser-cert/issue", {"csr_pem": csr_pem}, timeout=60.0)


# ---------------------------------------------------------------------------
# Browser certificates
#
# When the device has a BROWSER_CERTIFICATE policy, this user gets a short-lived certificate
# from the device CA. The key is generated INSIDE the user's NSS database (~/.pki/nssdb, the
# store Chrome, Chromium and GNOME Web read) with certutil and never leaves it, except for the
# copy into this user's own Firefox profiles. Only the CSR goes to spired. Certificates that
# SpireUEM did not add are never touched: every SpireUEM entry has a nickname starting with
# NICK_PREFIX and nothing else is listed, deleted or exported.
# ---------------------------------------------------------------------------

NICK_PREFIX = "SpireUEM Browser Certificate"
CA_NICK_PREFIX = "SpireUEM Device CA"
MIN_VALID_SECONDS = 600  # a certificate with less left than this is treated as expired
BROWSER_CERT_INTERVAL = 3 * 3600  # how often the client re-checks, in seconds
BROWSER_CERT_RETRY = 600
BROWSER_CERT_POLL = 900


class BrowserCertError(Exception):
    pass


class CertutilMissing(BrowserCertError):
    pass


def _nick_for(der_b64_pem: str, prefix: str = NICK_PREFIX) -> str:
    """Return the nickname for a PEM certificate: the fixed prefix plus the first 12 hex
    digits of its SHA-256 fingerprint, so each certificate has its own nickname and can be
    removed on its own."""
    body = "".join(
        ln for ln in der_b64_pem.strip().splitlines() if not ln.startswith("-----")
    )
    der = base64.b64decode(body)
    return f"{prefix} {hashlib.sha256(der).hexdigest()[:12]}"


def _parse_nss_time(text: str) -> datetime:
    return datetime.strptime(text.strip(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)


class BrowserCertManager:
    """Keeps a current SpireUEM browser certificate in the user's NSS database and Firefox
    profiles. All state-changing work goes through certutil/pk12util, run with a private
    environment so output is parseable."""

    def __init__(self, ipc, home=None, certutil=None, pk12util=None, now=None, runtime_dir=None):
        self.ipc = ipc
        self.home = home or os.path.expanduser("~")
        self._certutil = certutil
        self._pk12util = pk12util
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.runtime_dir = runtime_dir
        self.nssdb = os.path.join(self.home, ".pki", "nssdb")
        state_home = os.environ.get("XDG_STATE_HOME") or os.path.join(self.home, ".local", "state")
        self.state_path = os.path.join(state_home, "spire", "browser-cert.json")
        self.lock_path = os.path.join(state_home, "spire", "browser-cert.lock")
        self._warned_missing = False

    # ---- tools -----------------------------------------------------------------------

    def certutil_path(self) -> str:
        path = self._certutil or shutil.which("certutil")
        if not path or not os.access(path, os.X_OK):
            raise CertutilMissing(
                "Browser certificates need the 'certutil' tool. Ask your administrator to "
                "install the libnss3-tools package."
            )
        return path

    def _run(self, argv, check=True, input_text=None):
        env = dict(os.environ, LC_ALL="C", LANG="C", HOME=self.home)
        res = subprocess.run(
            argv, capture_output=True, text=True, env=env, input=input_text, timeout=120
        )
        if check and res.returncode != 0:
            raise BrowserCertError(f"{os.path.basename(argv[0])} failed: {res.stderr.strip() or res.stdout.strip()}")
        return res

    def _certutil_run(self, dbdir, *args, check=True):
        return self._run([self.certutil_path(), *args, "-d", f"sql:{dbdir}"], check=check)

    # ---- NSS database ----------------------------------------------------------------

    def ensure_db(self, dbdir=None):
        dbdir = dbdir or self.nssdb
        if os.path.exists(os.path.join(dbdir, "cert9.db")):
            return
        os.makedirs(dbdir, mode=0o700, exist_ok=True)
        self._certutil_run(dbdir, "-N", "--empty-password")

    def list_nicks(self, dbdir, prefix):
        """Nicknames in the database that start with prefix (and only those)."""
        res = self._certutil_run(dbdir, "-L", check=False)
        nicks = []
        for line in res.stdout.splitlines():
            line = line.rstrip()
            m = re.match(r"^(.*?)\s{2,}[A-Za-z]*,[A-Za-z]*,[A-Za-z]*\s*$", line)
            name = (m.group(1) if m else line).strip()
            if name.startswith(prefix):
                nicks.append(name)
        return nicks

    def key_ids(self, dbdir):
        """Map of key id -> nickname ('' for an orphan key) for every key in the database."""
        res = self._certutil_run(dbdir, "-K", check=False)
        out = {}
        for line in res.stdout.splitlines():
            m = re.match(r"^<\s*\d+>\s+\S+\s+([0-9a-f]{8,})\s+(.*)$", line.strip())
            if not m:
                continue
            label = m.group(2).strip()
            if label == "(orphan)":
                nick = ""
            else:
                nick = label.split(":", 1)[1] if ":" in label else label
            out[m.group(1)] = nick
        return out

    def cert_window(self, dbdir, nick):
        """(not_before, not_after, subject) of the certificate with this nickname."""
        res = self._certutil_run(dbdir, "-L", "-n", nick)
        nb = re.search(r"Not Before:\s*(.+)", res.stdout)
        na = re.search(r"Not After\s*:\s*(.+)", res.stdout)
        subj = re.search(r'Subject:\s*"([^"]*)"', res.stdout)
        if not (nb and na):
            raise BrowserCertError(f"cannot read the validity of {nick}")
        return _parse_nss_time(nb.group(1)), _parse_nss_time(na.group(1)), (subj.group(1) if subj else "")

    def cert_pem(self, dbdir, nick) -> str:
        return self._certutil_run(dbdir, "-L", "-n", nick, "-a").stdout

    # ---- selection -------------------------------------------------------------------

    def current_cert(self):
        """The newest usable SpireUEM certificate in the main database (with its private key),
        as (nick, not_before, not_after), or None."""
        keys = set(self.key_ids(self.nssdb).values())
        best = None
        for nick in self.list_nicks(self.nssdb, NICK_PREFIX):
            if nick not in keys:
                continue  # no private key in this database: unusable
            try:
                nb, na, _ = self.cert_window(self.nssdb, nick)
            except BrowserCertError:
                continue
            if (na - self.now()).total_seconds() < MIN_VALID_SECONDS or nb > self.now():
                continue
            if best is None or nb > best[1]:
                best = (nick, nb, na)
        return best

    def due(self, nb: datetime, na: datetime) -> bool:
        """True once two thirds of the lifetime have passed."""
        return self.now() >= nb + (na - nb) * 2 / 3

    # ---- enrolment -------------------------------------------------------------------

    def _private_dir(self):
        base = self.runtime_dir or os.environ.get("XDG_RUNTIME_DIR")
        if not base or not os.path.isdir(base):
            base = "/dev/shm" if os.path.isdir("/dev/shm") else None
        if not base:
            raise BrowserCertError("no private temporary directory (XDG_RUNTIME_DIR) is available")
        return tempfile.mkdtemp(prefix="spire-bc-", dir=base)

    def enroll(self):
        """Generate a key in the NSS database, get it certified through spired, import the
        certificate. Returns the new nickname. On failure the new key is removed again."""
        before = set(self.key_ids(self.nssdb))
        work = self._private_dir()
        new_key = None
        try:
            noise = os.path.join(work, "noise")
            with open(noise, "wb") as fh:
                fh.write(os.urandom(128))
            csr_path = os.path.join(work, "csr.pem")
            self._certutil_run(
                self.nssdb, "-R", "-s", "CN=SpireUEM browser certificate", "-k", "ec", "-q", "nistp256",
                "-Z", "SHA256", "-a", "-o", csr_path, "-z", noise,
            )
            added = set(self.key_ids(self.nssdb)) - before
            if len(added) != 1:
                raise BrowserCertError("could not find the new key in the database")
            new_key = next(iter(added))
            with open(csr_path) as fh:
                csr_pem = fh.read()
            resp = self.ipc.browser_cert_issue(csr_pem)
            leaf = (resp.get("certificate_pem") or "").strip()
            if "BEGIN CERTIFICATE" not in leaf:
                raise BrowserCertError("spired returned no certificate")
            nick = _nick_for(leaf)
            leaf_path = os.path.join(work, "leaf.pem")
            with open(leaf_path, "w") as fh:
                fh.write(leaf + "\n")
            self._certutil_run(self.nssdb, "-A", "-n", nick, "-t", "u,u,u", "-i", leaf_path)
            if self.key_ids(self.nssdb).get(new_key) != nick:
                # The certificate did not bind to the key we generated.
                self._certutil_run(self.nssdb, "-D", "-n", nick, check=False)
                raise BrowserCertError("the issued certificate does not match the generated key")
            ca = (resp.get("device_ca_pem") or "").strip()
            if "BEGIN CERTIFICATE" in ca:
                self.import_ca(self.nssdb, ca, work)
            return nick
        except BaseException:
            if new_key and self.key_ids(self.nssdb).get(new_key) == "":
                self._certutil_run(self.nssdb, "-F", "-k", new_key, check=False)
            raise
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def import_ca(self, dbdir, ca_pem, work):
        """Import the device CA with no trust, so the chain can be built. A browser does not
        start trusting servers because of it."""
        nick = _nick_for(ca_pem, CA_NICK_PREFIX)
        if nick in self.list_nicks(dbdir, CA_NICK_PREFIX):
            return
        path = os.path.join(work, "ca.pem")
        with open(path, "w") as fh:
            fh.write(ca_pem + "\n")
        self._certutil_run(dbdir, "-A", "-n", nick, "-t", ",,", "-i", path)
        for other in self.list_nicks(dbdir, CA_NICK_PREFIX):
            if other != nick:
                self._certutil_run(dbdir, "-D", "-n", other, check=False)

    def remove_other_certs(self, dbdir, keep):
        """Delete every SpireUEM browser certificate (and its key) except keep."""
        keys = self.key_ids(dbdir)
        by_nick = {}
        for kid, nick in keys.items():
            by_nick.setdefault(nick, []).append(kid)
        for nick in self.list_nicks(dbdir, NICK_PREFIX):
            if nick == keep:
                continue
            self._certutil_run(dbdir, "-D", "-n", nick, check=False)
            for kid in by_nick.get(nick, []):
                self._certutil_run(dbdir, "-F", "-k", kid, check=False)

    # ---- Firefox ---------------------------------------------------------------------

    def firefox_profiles(self):
        roots = [
            os.path.join(self.home, ".mozilla", "firefox"),
            os.path.join(self.home, "snap", "firefox", "common", ".mozilla", "firefox"),
            os.path.join(self.home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
        ]
        out = []
        for root in roots:
            if not os.path.isdir(root):
                continue
            for name in sorted(os.listdir(root)):
                d = os.path.join(root, name)
                if os.path.isfile(os.path.join(d, "cert9.db")):
                    out.append(d)
        return out

    def sync_firefox(self, nick):
        """Give each Firefox profile the same certificate and key. The key travels in a PKCS#12
        file protected by a random one-time password. The password and the file live in a
        private directory on tmpfs ($XDG_RUNTIME_DIR) and are deleted straight after, and the
        password is passed in a file, not on the command line."""
        profiles = [p for p in self.firefox_profiles() if nick not in self.list_nicks(p, NICK_PREFIX)]
        results = {}
        pk12util = self._pk12util or shutil.which("pk12util")
        for prof in self.firefox_profiles():
            if prof not in profiles:
                self.remove_other_certs(prof, nick)
        if not profiles:
            return results
        if not pk12util:
            for prof in profiles:
                results[prof] = "pk12util is missing (libnss3-tools)"
            return results
        work = self._private_dir()
        try:
            pw_file = os.path.join(work, "pw")
            fd = os.open(pw_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(base64.b64encode(os.urandom(24)).decode())
            p12 = os.path.join(work, "bundle.p12")
            self._run([pk12util, "-o", p12, "-n", nick, "-d", f"sql:{self.nssdb}", "-w", pw_file])
            for prof in profiles:
                # Older SpireUEM entries go first: when a certificate with the same subject is
                # already there, pk12util gives the new one the old nickname, which would make
                # the old and new entries impossible to tell apart. If the import then fails the
                # profile has no SpireUEM certificate until the next pass, which retries.
                self.remove_other_certs(prof, "")
                res = self._run([pk12util, "-i", p12, "-d", f"sql:{prof}", "-w", pw_file], check=False)
                if res.returncode != 0:
                    results[prof] = res.stderr.strip() or "import failed (a Firefox primary password may be set)"
                    continue
                if nick not in self.key_ids(prof).values() or nick not in self.list_nicks(prof, NICK_PREFIX):
                    results[prof] = "imported, but the key is not bound to the certificate"
                    continue
                results[prof] = "ok"
        finally:
            shutil.rmtree(work, ignore_errors=True)
        return results

    # ---- driver ----------------------------------------------------------------------

    def write_state(self, status, message="", not_after=None):
        os.makedirs(os.path.dirname(self.state_path), mode=0o700, exist_ok=True)
        doc = {
            "status": status,
            "message": message,
            "not_after": not_after.isoformat() if not_after else "",
            "updated": self.now().isoformat(),
        }
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(doc, fh)
        os.replace(tmp, self.state_path)

    def read_state(self):
        try:
            with open(self.state_path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {"status": "unknown", "message": ""}

    def sync(self):
        """One pass. Returns the status string. It never raises: the outcome is written to
        the state file and returned."""
        import fcntl

        os.makedirs(os.path.dirname(self.lock_path), mode=0o700, exist_ok=True)
        lock = open(self.lock_path, "w")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            lock.close()
            return "busy"
        try:
            try:
                cfg = self.ipc.browser_cert_config()
            except Exception as exc:  # spired not running, or refused
                self.write_state("error", f"Cannot reach the SpireUEM agent: {exc}")
                return "error"
            if not cfg.get("enabled"):
                self.write_state("disabled")
                return "disabled"
            if not cfg.get("eligible"):
                self.write_state("not_eligible", "Browser certificates are only issued to regular user accounts.")
                return "not_eligible"
            try:
                self.certutil_path()
                self.ensure_db()
                cur = self.current_cert()
                if cur is None or self.due(cur[1], cur[2]):
                    try:
                        nick = self.enroll()
                    except BrowserCertError:
                        if cur is None:
                            raise
                        # Renewal failed but the current certificate still works: keep it
                        # and try again later.
                        nick = cur[0]
                        self.write_state("error", "Renewal failed; the current certificate is still valid.", cur[2])
                        return "error"
                    self.remove_other_certs(self.nssdb, nick)
                    cur = self.current_cert()
                    if cur is None or cur[0] != nick:
                        raise BrowserCertError("the new certificate cannot be found after import")
                fx = self.sync_firefox(cur[0])
                bad = {p: m for p, m in fx.items() if m != "ok"}
                if bad:
                    self.write_state("ok", "Firefox profile not updated: " + "; ".join(sorted(set(bad.values()))), cur[2])
                else:
                    self.write_state("ok", "", cur[2])
                return "ok"
            except CertutilMissing as exc:
                if not self._warned_missing:
                    self._warned_missing = True
                    print(f"spire-hub: {exc}", file=sys.stderr)
                self.write_state("missing_certutil", str(exc))
                return "missing_certutil"
            except Exception as exc:
                self.write_state("error", str(exc))
                return "error"
        finally:
            lock.close()


def browser_cert_status_text(state: dict) -> str:
    """One short line for the client about the user's browser certificate."""
    status = state.get("status")
    if status == "ok":
        until = (state.get("not_after") or "")[:10]
        base = f"Installed, valid until {until}" if until else "Installed"
        return base + (f". {state['message']}" if state.get("message") else "")
    if status in ("error", "missing_certutil", "not_eligible"):
        return state.get("message") or "Not available"
    return ""


def browser_cert_daemon(ipc):
    """Background loop for the user session: sync now and every few hours."""
    mgr = BrowserCertManager(ipc)
    while True:
        result = mgr.sync()
        if result in ("ok", "missing_certutil"):
            time.sleep(BROWSER_CERT_INTERVAL)
        elif result in ("disabled", "not_eligible"):
            time.sleep(BROWSER_CERT_POLL)  # the local check is cheap; notice a new policy soon
        else:
            time.sleep(BROWSER_CERT_RETRY)


def get_status(socket_path: str = DEFAULT_SOCKET_PATH) -> dict:
    return SpireIPCClient(socket_path).get_status()


def trigger_sync(socket_path: str = DEFAULT_SOCKET_PATH) -> dict:
    return SpireIPCClient(socket_path).trigger_sync()


def get_catalog(socket_path: str = DEFAULT_SOCKET_PATH) -> list[dict]:
    return SpireIPCClient(socket_path).get_catalog()


def install_policy(policy_id: str, socket_path: str = DEFAULT_SOCKET_PATH) -> dict:
    return SpireIPCClient(socket_path).install_policy(policy_id)


def uninstall_policy(policy_id: str, socket_path: str = DEFAULT_SOCKET_PATH) -> dict:
    return SpireIPCClient(socket_path).uninstall_policy(policy_id)


def resolve_app_icon(name: str, app_id: str) -> str:
    app_lower = (app_id or "").lower()
    name_lower = (name or "").lower()
    if "code" in app_lower or "code" in name_lower or "visual studio" in name_lower:
        return "com.visualstudio.code"
    if "libreoffice" in app_lower or "libreoffice" in name_lower:
        return "libreoffice-main"
    if "firefox" in app_lower or "firefox" in name_lower:
        return "org.mozilla.firefox"
    if "vlc" in app_lower or "vlc" in name_lower:
        return "org.videolan.VLC"
    if app_id:
        return app_id
    return "application-x-executable"


def build_gtk_app():
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    class SpireHubWindow(Adw.ApplicationWindow):
        def __init__(self, app: Adw.Application, ipc_client: SpireIPCClient):
            super().__init__(application=app, title="Spire Hub")
            self.set_default_size(820, 600)
            self.ipc = ipc_client
            self.security_policy_rows: list[Gtk.Widget] = []
            self.mandatory_app_rows: list[Gtk.Widget] = []
            self.catalog_rows: list[Gtk.Widget] = []

            self.toast_overlay = Adw.ToastOverlay()
            self.set_content(self.toast_overlay)

            root_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            self.toast_overlay.set_child(root_box)

            header_bar = Adw.HeaderBar()
            self.view_stack = Adw.ViewStack()

            view_switcher = Adw.ViewSwitcher()
            view_switcher.set_stack(self.view_stack)
            view_switcher.set_policy(Adw.ViewSwitcherPolicy.WIDE)
            header_bar.set_title_widget(view_switcher)

            root_box.append(header_bar)
            root_box.append(self.view_stack)

            self._build_compliance_page()
            self._build_catalog_page()

            self.refresh_all_async()
            self.browser_certs = BrowserCertManager(self.ipc)
            self._sync_browser_cert_async()
            GLib.timeout_add_seconds(BROWSER_CERT_INTERVAL, self._on_browser_cert_timer)

        def _on_browser_cert_timer(self):
            self._sync_browser_cert_async()
            return True

        def _sync_browser_cert_async(self):
            def worker():
                result = self.browser_certs.sync()
                GLib.idle_add(self._apply_browser_cert, result)

            threading.Thread(target=worker, daemon=True).start()

        def _apply_browser_cert(self, result: str):
            state = self.browser_certs.read_state()
            text = browser_cert_status_text(state)
            self.row_browser_cert.set_visible(bool(text))
            self.row_browser_cert.set_subtitle(GLib.markup_escape_text(text))
            if result in ("error", "missing_certutil"):
                self.show_toast(text or "Browser certificate could not be updated")
            return False

        def show_toast(self, message: str):
            toast = Adw.Toast.new(message)
            toast.set_timeout(4)
            self.toast_overlay.add_toast(toast)

        def _make_status_tag(self, text: str, css_class: str) -> Gtk.Label:
            tag = Gtk.Label(label=text)
            tag.add_css_class("caption")
            tag.add_css_class("heading")
            tag.add_css_class(css_class)
            tag.set_valign(Gtk.Align.CENTER)
            return tag

        def _build_compliance_page(self):
            """
            Security Compliance View (Adw.PreferencesPage):
            - Group 1: "System & Security Baseline" (TPM 2.0 attestation, LUKS2 escrow, CIS audit pass rate, sysctl/dconf status)
            - Group 2: "Mandatory Applications" (Required software packages with "Compliant" or "Action Required: Install" tags)
            """
            self.compliance_page = Adw.PreferencesPage()

            # Group 0: Pending Updates & Campaign Deferral (prominently displayed when updates are pending)
            self.campaign_group = Adw.PreferencesGroup(
                title="Pending Updates &amp; Deferral",
                description="Interactive review and deferral of scheduled system patch campaigns.",
            )
            self.compliance_page.add(self.campaign_group)
            self.campaign_group.set_visible(False)

            self.expander_campaign = Adw.ExpanderRow(
                title="Updates Scheduled",
                subtitle="Checking for pending patch campaigns...",
            )
            campaign_icon = Gtk.Image.new_from_icon_name("software-update-available-symbolic")
            campaign_icon.set_pixel_size(32)
            self.expander_campaign.add_prefix(campaign_icon)

            self.defer_button = Gtk.Button(label="Defer")
            self.defer_button.add_css_class("pill")
            self.defer_button.set_valign(Gtk.Align.CENTER)
            self.defer_button.connect("clicked", self._on_defer_clicked)
            self.expander_campaign.add_action(self.defer_button)

            self.campaign_group.add(self.expander_campaign)
            self.campaign_package_rows: list[Gtk.Widget] = []

            # Retain self.row_campaign as alias for backward compatibility
            self.row_campaign = self.expander_campaign
            self.pending_campaign_id = ""

            # Group 1: System & Security Baseline
            self.baseline_group = Adw.PreferencesGroup(
                title="System &amp; Security Baseline",
                description="Hardware attestation, disk encryption escrow, CIS benchmark posture, and kernel/desktop security baselines.",
            )
            self.compliance_page.add(self.baseline_group)

            self.row_overall = Adw.ActionRow(
                title="Overall Endpoint Compliance",
                subtitle="Evaluating security baseline and mandatory software...",
            )
            self.overall_tag = self._make_status_tag("Evaluating", "dim-label")
            self.row_overall.add_suffix(self.overall_tag)

            self.sync_button = Gtk.Button(label="Sync Now")
            self.sync_button.add_css_class("suggested-action")
            self.sync_button.add_css_class("pill")
            self.sync_button.set_valign(Gtk.Align.CENTER)
            self.sync_button.connect("clicked", self._on_sync_clicked)
            self.row_overall.add_suffix(self.sync_button)
            self.baseline_group.add(self.row_overall)

            # Shown only while the device has a browser certificate policy.
            self.row_browser_cert = Adw.ActionRow(title="Browser certificate", subtitle="")
            self.row_browser_cert.set_visible(False)
            self.baseline_group.add(self.row_browser_cert)
            self.row_tpm = Adw.ActionRow(
                title="TPM 2.0 Attestation &amp; Secure Boot",
                subtitle="Checking hardware root of trust...",
            )
            self.baseline_group.add(self.row_tpm)

            self.row_luks = Adw.ActionRow(
                title="LUKS2 Recovery Key Escrow",
                subtitle="Checking volume envelope encryption escrow...",
            )
            self.baseline_group.add(self.row_luks)

            self.row_cis = Adw.ActionRow(
                title="CIS Audit Pass Rate",
                subtitle="OpenSCAP CIS Debian 12 Workstation Benchmark",
            )
            self.baseline_group.add(self.row_cis)

            self.row_sysctl_dconf = Adw.ActionRow(
                title="Kernel (sysctl) &amp; Desktop (dconf) Baseline Status",
                subtitle="Checking enforced security policies...",
            )
            self.baseline_group.add(self.row_sysctl_dconf)

            # Group 2: Mandatory Applications
            self.mandatory_group = Adw.PreferencesGroup(
                title="Mandatory Applications",
                description="Required enterprise applications that must be installed to maintain endpoint compliance.",
            )
            self.compliance_page.add(self.mandatory_group)

            self.view_stack.add_titled_with_icon(
                self.compliance_page,
                "compliance",
                "Security Compliance",
                "security-high-symbolic",
            )

        def _build_catalog_page(self):
            """
            App Catalog View (Adw.PreferencesPage):
            - Displays all optional and available software (e.g., LibreOffice, VS Code, Firefox Developer, VLC).
            - Renders operational action buttons only (Install, Open, Remove).
            - Explicitly omits all compliance tags, pass/fail indicators, or warning badges.
            """
            self.catalog_page = Adw.PreferencesPage()
            self.catalog_group = Adw.PreferencesGroup(
                title="App Catalog",
                description="Optional self-service enterprise software available for on-demand installation.",
            )
            self.catalog_page.add(self.catalog_group)

            self.view_stack.add_titled_with_icon(
                self.catalog_page,
                "catalog",
                "App Catalog",
                "software-store-symbolic",
            )

        def refresh_all_async(self):
            def worker():
                try:
                    status = self.ipc.get_status()
                except Exception as exc:
                    status = {"error": str(exc)}
                try:
                    catalog = self.ipc.get_catalog()
                except Exception:
                    catalog = []
                GLib.idle_add(self._apply_refresh, status, catalog)

            threading.Thread(target=worker, daemon=True).start()

        def _apply_refresh(self, status: dict, catalog: list[dict]):
            if "error" in status:
                self.row_overall.set_subtitle(f"Disconnected ({status['error']})")
                self.overall_tag.set_label("Offline")
                self.overall_tag.set_css_classes(["caption", "heading", "warning"])
            else:
                is_compliant = bool(status.get("is_compliant", True))
                last_sync = status.get("last_checkin_at") or "Never"
                if is_compliant:
                    self.row_overall.set_subtitle(
                        f"This device is compliant | Last checked: {last_sync}"
                    )
                    self.overall_tag.set_label("Compliant")
                    self.overall_tag.set_css_classes(["caption", "heading", "success"])
                else:
                    self.row_overall.set_subtitle(
                        f"Action required to restore compliance | Last checked: {last_sync}"
                    )
                    self.overall_tag.set_label("Non-Compliant")
                    self.overall_tag.set_css_classes(["caption", "heading", "error"])

                # Pending patch-campaign install (Defer button and interactive package inspection)
                pending = status.get("pending_campaign")
                if pending and isinstance(pending, dict):
                    self.pending_campaign_id = pending.get("campaign_id", "")
                    name = pending.get("name") or "Security updates"
                    left = pending.get("deferrals_left", 0)
                    grace = pending.get("grace_seconds", 0)
                    may_defer = bool(pending.get("may_defer", False))
                    deadline_passed = bool(pending.get("deadline_passed", False))

                    self.expander_campaign.set_title(name)
                    if may_defer and left > 0:
                        sub = f"Installation scheduled | {left} deferral(s) remaining"
                        if grace > 0:
                            sub += f" | Grace window: {grace}s"
                        self.expander_campaign.set_subtitle(sub)
                        self.defer_button.set_label(f"Defer ({left} left)")
                        self.defer_button.set_sensitive(True)
                        self.defer_button.set_visible(True)
                    else:
                        sub = "Installation proceeding (Deadline reached)" if deadline_passed else "Installation proceeding (No deferrals remaining)"
                        self.expander_campaign.set_subtitle(sub)
                        self.defer_button.set_sensitive(False)
                        self.defer_button.set_visible(False)

                    # Clear previous package rows
                    for old_pkg_row in self.campaign_package_rows:
                        self.expander_campaign.remove(old_pkg_row)
                    self.campaign_package_rows.clear()

                    packages = pending.get("packages") or []
                    if packages:
                        for pkg in packages:
                            if isinstance(pkg, dict):
                                pkg_name = pkg.get("package", "Package")
                                target = pkg.get("target", "")
                                cve = pkg.get("from_cve", "")
                            else:
                                pkg_name = str(pkg)
                                target = ""
                                cve = ""
                            sub_parts = []
                            if target:
                                sub_parts.append(f"Target: {target}")
                            if cve:
                                sub_parts.append(f"Resolves: {cve}")
                            p_row = Adw.ActionRow(
                                title=pkg_name,
                                subtitle=" | ".join(sub_parts) if sub_parts else "Scheduled update package",
                            )
                            p_img = Gtk.Image.new_from_icon_name("package-x-generic-symbolic")
                            p_img.set_pixel_size(24)
                            p_row.add_prefix(p_img)
                            self.expander_campaign.add_row(p_row)
                            self.campaign_package_rows.append(p_row)
                    else:
                        pkg_names = pending.get("package_names") or []
                        for pname in pkg_names:
                            p_row = Adw.ActionRow(
                                title=str(pname),
                                subtitle="Scheduled update package",
                            )
                            p_img = Gtk.Image.new_from_icon_name("package-x-generic-symbolic")
                            p_img.set_pixel_size(24)
                            p_row.add_prefix(p_img)
                            self.expander_campaign.add_row(p_row)
                            self.campaign_package_rows.append(p_row)

                    self.expander_campaign.set_expanded(True)
                    self.campaign_group.set_visible(True)
                    self.expander_campaign.set_visible(True)
                else:
                    self.pending_campaign_id = ""
                    self.campaign_group.set_visible(False)
                    self.expander_campaign.set_visible(False)
                    for old_pkg_row in self.campaign_package_rows:
                        self.expander_campaign.remove(old_pkg_row)
                    self.campaign_package_rows.clear()

                # 1. TPM 2.0 & Secure Boot
                att_status = status.get("attestation_status", "UNATTESTED")
                sec_boot = "Enabled" if status.get("secure_boot_enabled") else "Disabled"
                self.row_tpm.set_subtitle(
                    f"TPM 2.0 Quote: {att_status} | UEFI Secure Boot: {sec_boot}"
                )

                # 2. LUKS2 Escrow
                luks_ok = status.get("luks_escrowed", True)
                self.row_luks.set_subtitle(
                    "RSA-OAEP-4096 + AES-256-GCM Recovery Key Escrowed"
                    if luks_ok
                    else "Awaiting LUKS2 Volume Escrow"
                )

                # 3. CIS Audit Pass Rate
                cis_score = status.get("cis_audit_score") or 0.0
                if cis_score > 0:
                    self.row_cis.set_subtitle(f"Pass Rate: {cis_score:.1f}% (CIS Level 1 Workstation)")
                else:
                    self.row_cis.set_subtitle("Managed by OpenSCAP CIS Benchmark Engine")

                # 4. Security & Configuration Baseline Policies (sysctl, dconf, apt, etc.)
                sec_policies = status.get("security_policies") or []
                sec_passed = sum(1 for p in sec_policies if p.get("is_compliant") or p.get("status") == "COMPLIANT")
                sec_total = len(sec_policies)
                if sec_total > 0:
                    self.row_sysctl_dconf.set_subtitle(
                        f"{sec_passed} of {sec_total} security &amp; configuration baselines compliant"
                    )
                else:
                    comp_count = status.get("compliant_policies", 0)
                    total_count = status.get("total_policies", 0)
                    self.row_sysctl_dconf.set_subtitle(
                        f"{comp_count} of {total_count} baseline policies active"
                    )

                for old_row in self.security_policy_rows:
                    self.baseline_group.remove(old_row)
                self.security_policy_rows.clear()

                for sp in sec_policies:
                    sp_compliant = bool(sp.get("is_compliant") or sp.get("status") == "COMPLIANT")
                    sp_row = Adw.ActionRow(
                        title=sp.get("name", "Security Policy"),
                        subtitle=f"Type: {sp.get('policy_type', 'BASELINE')}",
                    )
                    sp_tag = self._make_status_tag(
                        "Compliant" if sp_compliant else str(sp.get("status", "Non-Compliant")),
                        "success" if sp_compliant else "error",
                    )
                    sp_row.add_suffix(sp_tag)
                    self.baseline_group.add(sp_row)
                    self.security_policy_rows.append(sp_row)

                # Populate Group 2: Mandatory Applications
                for old_row in self.mandatory_app_rows:
                    self.mandatory_group.remove(old_row)
                self.mandatory_app_rows.clear()

                mandatory_apps = status.get("mandatory_apps") or []
                if not mandatory_apps:
                    empty_row = Adw.ActionRow(
                        title="No Mandatory Applications Assigned",
                        subtitle="All required software baselines are satisfied.",
                    )
                    tag = self._make_status_tag("Compliant", "success")
                    empty_row.add_suffix(tag)
                    self.mandatory_group.add(empty_row)
                    self.mandatory_app_rows.append(empty_row)
                else:
                    for app_item in mandatory_apps:
                        app_name = app_item.get("name", "Required Application")
                        app_ver = app_item.get("version") or "latest"
                        app_id = app_item.get("app_id") or ""
                        pol_id = app_item.get("policy_id") or app_id
                        installed = bool(app_item.get("installed") or app_item.get("is_compliant"))

                        row = Adw.ActionRow(
                            title=app_name,
                            subtitle=f"Version: {app_ver} ({app_id})" if app_id else f"Version: {app_ver}",
                        )
                        img = Gtk.Image.new_from_icon_name(resolve_app_icon(app_name, app_id))
                        img.set_pixel_size(32)
                        row.add_prefix(img)

                        suffix_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                        suffix_box.set_valign(Gtk.Align.CENTER)

                        if installed:
                            tag = self._make_status_tag("Compliant", "success")
                            suffix_box.append(tag)
                        else:
                            tag = self._make_status_tag("Action Required: Install", "error")
                            suffix_box.append(tag)
                            btn_inst = Gtk.Button(label="Install")
                            btn_inst.add_css_class("pill")
                            btn_inst.add_css_class("suggested-action")
                            btn_inst.set_valign(Gtk.Align.CENTER)
                            btn_inst.connect(
                                "clicked", self._on_install_clicked, pol_id, app_name
                            )
                            suffix_box.append(btn_inst)

                        row.add_suffix(suffix_box)
                        self.mandatory_group.add(row)
                        self.mandatory_app_rows.append(row)

            # Populate App Catalog View (strictly non-evaluative: operational buttons Install, Open, Remove only)
            for old_row in self.catalog_rows:
                self.catalog_group.remove(old_row)
            self.catalog_rows.clear()

            available_items = status.get("available_catalog") if isinstance(status, dict) else None
            catalog_source = available_items if available_items else catalog

            for item in catalog_source:
                payload = item.get("payload") or {}
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except Exception:
                        payload = {}

                app_id = str(
                    item.get("app_id")
                    or payload.get("app_id")
                    or payload.get("package_name")
                    or payload.get("package")
                    or ""
                )
                app_ver = str(item.get("version") or payload.get("version") or "latest")
                app_name = item.get("name", "Catalog Application")
                desc = item.get("description") or f"Version: {app_ver}"

                row = Adw.ActionRow(
                    title=app_name,
                    subtitle=desc,
                )

                img = Gtk.Image.new_from_icon_name(resolve_app_icon(app_name, app_id))
                img.set_pixel_size(32)
                row.add_prefix(img)

                pol_id = item.get("policy_id", "")
                installed = bool(item.get("installed"))

                action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                action_box.set_valign(Gtk.Align.CENTER)

                if installed:
                    btn_open = Gtk.Button(label="Open")
                    btn_open.add_css_class("pill")
                    btn_open.set_valign(Gtk.Align.CENTER)
                    btn_open.connect(
                        "clicked", self._on_open_clicked, app_id, item.get("policy_type", "")
                    )
                    action_box.append(btn_open)

                    btn_remove = Gtk.Button(label="Remove")
                    btn_remove.add_css_class("pill")
                    btn_remove.add_css_class("destructive-action")
                    btn_remove.set_valign(Gtk.Align.CENTER)
                    btn_remove.connect(
                        "clicked", self._on_uninstall_clicked, pol_id, app_name
                    )
                    action_box.append(btn_remove)
                else:
                    btn_inst = Gtk.Button(label="Install")
                    btn_inst.add_css_class("pill")
                    btn_inst.add_css_class("suggested-action")
                    btn_inst.set_valign(Gtk.Align.CENTER)
                    btn_inst.connect(
                        "clicked", self._on_install_clicked, pol_id, app_name
                    )
                    action_box.append(btn_inst)

                row.add_suffix(action_box)
                self.catalog_group.add(row)
                self.catalog_rows.append(row)

            return False

        def _on_open_clicked(self, _btn: Gtk.Button, app_id: str, policy_type: str):
            if not app_id:
                return
            try:
                if policy_type == "FLATPAK_APP":
                    subprocess.Popen(["flatpak", "run", app_id])
                else:
                    subprocess.Popen([app_id])
            except Exception as exc:
                self.show_toast(f"Unable to launch {app_id}: {exc}")

        def _on_defer_clicked(self, btn: Gtk.Button):
            campaign_id = self.pending_campaign_id
            if not campaign_id:
                return
            btn.set_sensitive(False)

            def worker():
                try:
                    res = self.ipc.defer_campaign(campaign_id)
                    GLib.idle_add(self._on_defer_complete, btn, res, None)
                except Exception as exc:
                    GLib.idle_add(self._on_defer_complete, btn, None, str(exc))

            threading.Thread(target=worker, daemon=True).start()

        def _on_defer_complete(self, btn: Gtk.Button, res: dict | None, error_msg: str | None):
            if error_msg:
                btn.set_sensitive(True)
                btn.set_label("Defer")
                self.show_toast(f"Could not defer: {error_msg}")
            elif res and res.get("deferred"):
                self.show_toast("Updates deferred successfully; installation rescheduled")
                self.expander_campaign.set_subtitle("Updates deferred. Rescheduling...")
                btn.set_label("Deferred")
                btn.set_sensitive(False)
                self.campaign_group.set_visible(False)
                self.expander_campaign.set_visible(False)
                self.refresh_all_async()
            else:
                btn.set_sensitive(False)
                btn.set_label("Cannot Defer")
                msg = (res.get("message") if res else None) or "No more deferrals available; updates will install now"
                self.show_toast(msg)
            return False

        def _on_sync_clicked(self, btn: Gtk.Button):
            btn.set_sensitive(False)
            btn.set_label("Syncing...")

            def worker():
                try:
                    self.ipc.trigger_sync()
                    GLib.idle_add(self._on_sync_complete, btn, None)
                except Exception as exc:
                    GLib.idle_add(self._on_sync_complete, btn, str(exc))

            threading.Thread(target=worker, daemon=True).start()

        def _on_sync_complete(self, btn: Gtk.Button, error_msg: str | None):
            btn.set_sensitive(True)
            btn.set_label("Sync Now")
            if error_msg:
                self.show_toast(f"Sync failed: {error_msg}")
            else:
                self.show_toast("Device synchronized with SpireUEM server")
                self.refresh_all_async()
            return False

        def _on_install_clicked(self, btn: Gtk.Button, policy_id: str, policy_name: str):
            btn.set_sensitive(False)
            btn.set_label("Installing...")

            def worker():
                try:
                    self.ipc.install_policy(policy_id)
                    GLib.idle_add(self._on_install_complete, btn, policy_name, None)
                except Exception as exc:
                    GLib.idle_add(self._on_install_complete, btn, policy_name, str(exc))

            threading.Thread(target=worker, daemon=True).start()

        def _on_install_complete(
            self, btn: Gtk.Button, policy_name: str, error_msg: str | None
        ):
            if error_msg:
                btn.set_sensitive(True)
                btn.set_label("Install")
                self.show_toast(f"Failed to install {policy_name}: {error_msg}")
            else:
                self.show_toast(f"Installed {policy_name}")
                self.refresh_all_async()
            return False

        def _on_uninstall_clicked(self, btn: Gtk.Button, policy_id: str, policy_name: str):
            btn.set_sensitive(False)
            btn.set_label("Removing...")

            def worker():
                try:
                    self.ipc.uninstall_policy(policy_id)
                    GLib.idle_add(self._on_uninstall_complete, btn, policy_name, None)
                except Exception as exc:
                    GLib.idle_add(self._on_uninstall_complete, btn, policy_name, str(exc))

            threading.Thread(target=worker, daemon=True).start()

        def _on_uninstall_complete(
            self, btn: Gtk.Button, policy_name: str, error_msg: str | None
        ):
            if error_msg:
                btn.set_sensitive(True)
                btn.set_label("Remove")
                self.show_toast(f"Failed to remove {policy_name}: {error_msg}")
            else:
                self.show_toast(f"Removed {policy_name}")
                self.refresh_all_async()
            return False

    class SpireHubApp(Adw.Application):
        def __init__(self):
            super().__init__(application_id=APP_ID)
            self.ipc = SpireIPCClient()

        def do_activate(self):
            win = self.props.active_window
            if not win:
                win = SpireHubWindow(self, self.ipc)
            win.present()

    return SpireHubApp()


def main():
    global sys
    # Normalize sys.argv when invoked via python3 -c "... hubScript ..."
    if len(sys.argv) > 1 and sys.argv[0] == "-c":
        sys.argv = sys.argv[1:]

    if "--check-ipc" in sys.argv:
        status = get_status()
        catalog = get_catalog()
        print(json.dumps({"status": status, "catalog": catalog}))
        return 0

    if len(sys.argv) > 2 and sys.argv[1] == "--defer":
        cid = sys.argv[2]
        res = SpireIPCClient().defer_campaign(cid)
        print(json.dumps(res))
        return 0

    if "--browser-cert-sync" in sys.argv:
        mgr = BrowserCertManager(SpireIPCClient())
        result = mgr.sync()
        print(json.dumps({"result": result, "state": mgr.read_state()}))
        return 0 if result in ("ok", "disabled", "not_eligible", "busy") else 1

    if "--browser-cert-daemon" in sys.argv:
        browser_cert_daemon(SpireIPCClient())
        return 0

    app = build_gtk_app()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
