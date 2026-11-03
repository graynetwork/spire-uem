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
}

// GetPolicyTemplateByID looks up an enterprise policy preset by its template ID.
func GetPolicyTemplateByID(id string) (*PolicyTemplate, bool) {
	for i := range EnterprisePolicyTemplates {
		if EnterprisePolicyTemplates[i].ID == id {
			return &EnterprisePolicyTemplates[i], true
		}
	}
	return nil, false
}
