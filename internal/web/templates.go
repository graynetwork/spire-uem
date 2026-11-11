package web

import "github.com/spire-uem/spire-uem/internal/types"

// ZeroTouchAgentUpgradesTemplate defines the out-of-the-box policy template for zero-touch agent upgrades.
var ZeroTouchAgentUpgradesTemplate = types.PolicyTemplate{
	ID:          "enable-zero-touch-agent-upgrades",
	Name:        "Enable Zero-Touch Agent Upgrades",
	Description: "Configures unattended-upgrades to automatically install SpireUEM agent updates from the internal APT repository without requiring host reboot.",
	PolicyType:  types.PolicyTypeAptConfig,
	Payload: []byte(`{
		"file_name": "52spire-unattended-upgrades",
		"content": "// Allow zero-touch automated updates from the internal Spire repository\nUnattended-Upgrade::Origins-Pattern {\n    \"origin=SpireUEM,codename=${distro_codename},label=SpireUEM\";\n    \"origin=SpireUEM,suite=stable,label=SpireUEM\";\n};\n\n// Ensure daemon restart occurs without requiring a host reboot\nUnattended-Upgrade::Automatic-Reboot \"false\";\n\n// Non-interactive upgrade defaults (prevent debconf/needrestart prompts)\nDpkg::Options {\n    \"--force-confdef\";\n    \"--force-confold\";\n};\n"
	}`),
}

// EnterprisePolicyTemplates re-exports the enterprise policy presets from internal/types.
var EnterprisePolicyTemplates = types.EnterprisePolicyTemplates

// GetPolicyTemplateByID re-exports the preset template lookup function.
var GetPolicyTemplateByID = types.GetPolicyTemplateByID
