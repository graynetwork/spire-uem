#!/usr/bin/env python3
"""
SpireUEM Graphical Desktop Client (spire-hub)
Native GTK4 + Libadwaita-1 desktop client communicating over /run/spire/agent.sock.
Strictly separates Security Compliance (System & Security Baseline + Mandatory Applications)
from the non-evaluative Self-Service App Catalog.
"""

import http.client
import json
import os
import socket
import subprocess
import sys
import threading

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

    app = build_gtk_app()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
