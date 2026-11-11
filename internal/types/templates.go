package types

import "encoding/json"

// PolicyTemplate represents a pre-configured enterprise policy preset.
type PolicyTemplate struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	PolicyType  PolicyType      `json:"policy_type"`
	Payload     json.RawMessage `json:"payload"`
}

// EnterprisePolicyTemplates holds the built-in enterprise baseline presets.
var EnterprisePolicyTemplates = []PolicyTemplate{
	{
		ID:          "corporate-desktop-baseline",
		Name:        "Corporate Desktop Baseline",
		Description: "Enforces corporate GNOME workstation baseline: 15-min idle lock, privacy masking, thegraylan wallpaper, and GDM security banner.",
		PolicyType:  PolicyTypeDconfSetting,
		Payload: json.RawMessage(`{
			"file_name": "00-corporate-workstation",
			"locked": true,
			"sections": {
				"org/gnome/desktop/session": {
					"idle-delay": "uint32 900"
				},
				"org/gnome/desktop/screensaver": {
					"lock-enabled": "true",
					"lock-delay": "uint32 0",
					"show-notifications": "false",
					"user-switch-enabled": "false"
				},
				"org/gnome/desktop/notifications": {
					"show-in-lock-screen": "false"
				},
				"org/gnome/desktop/background": {
					"picture-uri": "'file:///usr/share/backgrounds/corporate/thegraylan-wallpaper.png'",
					"picture-uri-dark": "'file:///usr/share/backgrounds/corporate/thegraylan-wallpaper.png'",
					"picture-options": "'zoom'",
					"primary-color": "'#0b0f19'",
					"secondary-color": "'#0b0f19'"
				},
				"org/gnome/login-screen": {
					"banner-message-enable": "true",
					"banner-message-text": "'Authorized corporate use only. System activities are subject to monitoring and auditing.'"
				}
			},
			"locks": [
				"/org/gnome/desktop/session/idle-delay",
				"/org/gnome/desktop/screensaver/lock-enabled",
				"/org/gnome/desktop/screensaver/lock-delay",
				"/org/gnome/desktop/screensaver/show-notifications",
				"/org/gnome/desktop/screensaver/user-switch-enabled",
				"/org/gnome/desktop/notifications/show-in-lock-screen",
				"/org/gnome/desktop/background/picture-uri",
				"/org/gnome/desktop/background/picture-uri-dark",
				"/org/gnome/desktop/background/picture-options",
				"/org/gnome/login-screen/banner-message-enable",
				"/org/gnome/login-screen/banner-message-text"
			]
		}`),
	},
	{
		ID:          "gnome-wallpaper-lock",
		Name:        "GNOME Corporate Wallpaper Lock",
		Description: "Sets org/gnome/desktop/background picture-uri to 'file:///usr/share/backgrounds/spire-managed.png' with mandatory dconf key lock.",
		PolicyType:  PolicyTypeDconfSetting,
		Payload:     json.RawMessage(`{"schema_path":"org/gnome/desktop/background","key":"picture-uri","value":"'file:///usr/share/backgrounds/spire-managed.png'","locked":true}`),
	},
	{
		ID:          "unattended-upgrades-install",
		Name:        "Enforce Unattended Security Upgrades",
		Description: "Ensures the unattended-upgrades package is installed across Debian endpoints for automated security patching.",
		PolicyType:  PolicyTypePackagePresence,
		Payload:     json.RawMessage(`{"package_name":"unattended-upgrades"}`),
	},
	{
		ID:          "disable-usb-automount",
		Name:        "Disable USB Media Automount",
		Description: "Locks org/gnome/desktop/media-handling automount and automount-open to false to prevent rogue removable media execution.",
		PolicyType:  PolicyTypeDconfSetting,
		Payload:     json.RawMessage(`{"schema_path":"org/gnome/desktop/media-handling","key":"automount","value":"false","extra_settings":{"automount-open":"false"},"locked":true}`),
	},
	{
		ID:          "firefox-esr-flatpak",
		Name:        "Deploy Mozilla Firefox (Flatpak)",
		Description: "Ensures org.mozilla.firefox is installed system-wide from Flathub on targeted desktop endpoints.",
		PolicyType:  PolicyTypeFlatpakApp,
		Payload:     json.RawMessage(`{"app_id":"org.mozilla.firefox","state":"present","remote":"flathub"}`),
	},
	{
		ID:          "libreoffice-flatpak",
		Name:        "Deploy LibreOffice Suite (Flatpak)",
		Description: "Ensures org.libreoffice.LibreOffice is installed system-wide from Flathub on targeted desktop endpoints.",
		PolicyType:  PolicyTypeFlatpakApp,
		Payload:     json.RawMessage(`{"app_id":"org.libreoffice.LibreOffice","state":"present","remote":"flathub"}`),
	},
	{
		ID:          "vscode-flatpak",
		Name:        "Visual Studio Code (Flatpak)",
		Description: "Installs Microsoft Visual Studio Code IDE (com.visualstudio.code) from Flathub for development and engineering workstations.",
		PolicyType:  PolicyTypeFlatpakApp,
		Payload:     json.RawMessage(`{"app_id":"com.visualstudio.code","state":"present","remote":"flathub"}`),
	},
	{
		ID:          "cis-debian12-network-hardening",
		Name:        "CIS Debian 12 Network Hardening",
		Description: "Enforces CIS Benchmark sysctl network parameters (rp_filter, icmp echo broadcasts, redirects, syncookies, log_martians).",
		PolicyType:  PolicyTypeSysctlSetting,
		Payload: json.RawMessage(`{
			"net.ipv4.conf.all.rp_filter": "1",
			"net.ipv4.conf.default.rp_filter": "1",
			"net.ipv4.icmp_echo_ignore_broadcasts": "1",
			"net.ipv4.conf.all.accept_redirects": "0",
			"net.ipv4.conf.default.accept_redirects": "0",
			"net.ipv4.conf.all.send_redirects": "0",
			"net.ipv4.conf.default.send_redirects": "0",
			"net.ipv4.tcp_syncookies": "1",
			"net.ipv4.conf.all.log_martians": "1"
		}`),
	},
	{
		ID:          "cis-debian12-gnome-lockout",
		Name:        "CIS Debian 12 GNOME Screen Lockout",
		Description: "Enforces CIS Benchmark GNOME desktop idle delay (300s) and screensaver lock-delay (0s) with mandatory locks.",
		PolicyType:  PolicyTypeDconfSetting,
		Payload: json.RawMessage(`{
			"file_name": "01-cis-screen-lock",
			"locked": true,
			"sections": {
				"org/gnome/desktop/session": {
					"idle-delay": "uint32 300"
				},
				"org/gnome/desktop/screensaver": {
					"lock-enabled": "true",
					"lock-delay": "uint32 0"
				}
			}
		}`),
	},
	{
		ID:          "enable-zero-touch-agent-upgrades",
		Name:        "Enable Zero-Touch Agent Upgrades",
		Description: "Configures unattended-upgrades to automatically install SpireUEM agent updates from the internal APT repository without requiring host reboot.",
		PolicyType:  PolicyTypeAptConfig,
		Payload: json.RawMessage(`{
			"file_name": "52spire-unattended-upgrades",
			"content": "// Allow zero-touch automated updates from the internal Spire repository\nUnattended-Upgrade::Origins-Pattern {\n    \"origin=SpireUEM,codename=${distro_codename},label=SpireUEM\";\n    \"origin=SpireUEM,suite=stable,label=SpireUEM\";\n};\n\n// Ensure daemon restart occurs without requiring a host reboot\nUnattended-Upgrade::Automatic-Reboot \"false\";\n\n// Non-interactive upgrade defaults (prevent debconf/needrestart prompts)\nDpkg::Options {\n    \"--force-confdef\";\n    \"--force-confold\";\n};\n"
		}`),
	},
	{
		ID:          "cis-debian12-kernel-memory-hardening",
		Name:        "CIS Debian 12 Kernel & Memory Protection",
		Description: "Enforces kernel address space layout randomization (ASLR) and disables SUID coredumps.",
		PolicyType:  PolicyTypeSysctlSetting,
		Payload: json.RawMessage(`{
			"fs.suid_dumpable": "0",
			"kernel.randomize_va_space": "2"
		}`),
	},
	{
		ID:          "cis-debian12-package-rsyslog",
		Name:        "CIS Debian 12 System Logging (rsyslog)",
		Description: "Ensures rsyslog package is installed for system event and audit trail logging.",
		PolicyType:  PolicyTypePackagePresence,
		Payload:     json.RawMessage(`{"package_name": "rsyslog"}`),
	},
	{
		ID:          "cis-debian12-package-auditd",
		Name:        "CIS Debian 12 Audit Framework (auditd)",
		Description: "Ensures the auditd security logging daemon package is installed.",
		PolicyType:  PolicyTypePackagePresence,
		Payload:     json.RawMessage(`{"package_name": "auditd"}`),
	},
	{
		ID:          "cis-debian12-package-ntpsec",
		Name:        "CIS Debian 12 Network Time Protocol (ntpsec)",
		Description: "Ensures ntpsec is installed for synchronized host time across the fleet.",
		PolicyType:  PolicyTypePackagePresence,
		Payload:     json.RawMessage(`{"package_name": "ntpsec"}`),
	},
	{
		ID:          "cis-debian12-service-rsyslog",
		Name:        "CIS Debian 12 Enable rsyslog Service",
		Description: "Enables and starts the rsyslog systemd service for reliable event logging.",
		PolicyType:  PolicyTypeSystemdService,
		Payload:     json.RawMessage(`{"service_name": "rsyslog", "state": "started", "enabled": true}`),
	},
	{
		ID:          "cis-debian12-service-logrotate",
		Name:        "CIS Debian 12 Enable logrotate Timer",
		Description: "Enables and starts the logrotate systemd timer for automatic log archiving and rotation.",
		PolicyType:  PolicyTypeSystemdService,
		Payload:     json.RawMessage(`{"service_name": "logrotate.timer", "state": "started", "enabled": true}`),
	},
}

// BenchmarkRuleRemediationMap maps OpenSCAP CIS rule identifiers to preset template IDs.
var BenchmarkRuleRemediationMap = map[string]string{
	"sysctl_net_ipv4_conf_all_rp_filter":          "cis-debian12-network-hardening",
	"sysctl_net_ipv4_icmp_echo_ignore_broadcasts": "cis-debian12-network-hardening",
	"dconf_gnome_screensaver_lock_enabled":        "cis-debian12-gnome-lockout",
	"sysctl_fs_suid_dumpable":                     "cis-debian12-kernel-memory-hardening",
	"sysctl_kernel_randomize_va_space":            "cis-debian12-kernel-memory-hardening",
	"package_rsyslog_installed":                   "cis-debian12-package-rsyslog",
	"package_audit_installed":                     "cis-debian12-package-auditd",
	"package_ntp_installed":                       "cis-debian12-package-ntpsec",
	"service_rsyslog_enabled":                     "cis-debian12-service-rsyslog",
	"ensure_logrotate_activated":                  "cis-debian12-service-logrotate",
}

// GetTemplateForBenchmarkRule returns the template ID mapped to the given benchmark rule ID, if any.
func GetTemplateForBenchmarkRule(ruleID string) (string, bool) {
	if t, ok := BenchmarkRuleRemediationMap[ruleID]; ok {
		return t, true
	}
	const prefix = "xccdf_org.ssgproject.content_rule_"
	for k, v := range BenchmarkRuleRemediationMap {
		if ruleID == prefix+k || ruleID == k {
			return v, true
		}
	}
	return "", false
}

// GetPolicyTemplateByID looks up an enterprise policy preset by its template ID.
func GetPolicyTemplateByID(id string) (*PolicyTemplate, bool) {
	for i := range EnterprisePolicyTemplates {
		if EnterprisePolicyTemplates[i].ID == id {
			return &EnterprisePolicyTemplates[i], true
		}
	}
	if id == "00-corporate-workstation" || id == "corporate-baseline" {
		return GetPolicyTemplateByID("corporate-desktop-baseline")
	}
	return nil, false
}
