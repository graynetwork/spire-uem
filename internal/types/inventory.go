package types

import "time"

// InventoryReport is the rich hardware/software/network/security snapshot a device reports,
// at most once per inventory_interval, in CheckinRequest.Inventory. Every field is optional:
// an old agent omits the whole object, and a collector that cannot read a fact leaves its
// field at the zero value. The server validates and clamps everything; it never trusts a
// count or length an agent sends.
//
// Scalar facts flatten to device_attributes (source "inventory") under the fixed key
// catalogue in internal/db/inventory_keys.go. The large lists (packages, kernel modules,
// listening services, local accounts, USB devices, CA certificates) are stored in their own
// tables, replaced wholesale on each report.
type InventoryReport struct {
	// CollectedAt is when the agent gathered this snapshot (RFC 3339, agent clock).
	CollectedAt time.Time `json:"collected_at,omitempty"`

	HW   HardwareInfo   `json:"hw"`
	Net  NetworkInfo    `json:"net"`
	SW   SoftwareInfo   `json:"sw"`
	Sec  SecurityInfo   `json:"sec"`

	// Truncated is set by the agent when it dropped entries from one or more lists to stay
	// under its own size cap. The server surfaces it so an operator knows a list is partial.
	Truncated bool `json:"truncated,omitempty"`
}

// HardwareInfo holds scalar hardware facts plus the small enumerations (disks, GPUs) that
// stay inline because they are few.
type HardwareInfo struct {
	CPUModel   string `json:"cpu_model,omitempty"`
	CPUCores   int    `json:"cpu_cores,omitempty"`
	CPUThreads int    `json:"cpu_threads,omitempty"`
	MemoryMB   int64  `json:"memory_mb,omitempty"`

	SystemVendor  string `json:"system_vendor,omitempty"`
	SystemProduct string `json:"system_product,omitempty"`
	SystemSerial  string `json:"system_serial,omitempty"`
	BoardVendor   string `json:"board_vendor,omitempty"`
	BoardProduct  string `json:"board_product,omitempty"`
	BIOSVendor    string `json:"bios_vendor,omitempty"`
	BIOSVersion   string `json:"bios_version,omitempty"`
	BIOSDate      string `json:"bios_date,omitempty"`

	TPMPresent bool   `json:"tpm_present,omitempty"`
	TPMVersion string `json:"tpm_version,omitempty"` // e.g. "2.0"

	Virtualization string `json:"virtualization,omitempty"` // systemd-detect-virt, "none" on bare metal
	MonitorCount   int    `json:"monitor_count,omitempty"`

	Battery *BatteryInfo `json:"battery,omitempty"`

	Disks []DiskInfo `json:"disks,omitempty"`
	GPUs  []GPUInfo  `json:"gpus,omitempty"`
}

// BatteryInfo is the primary battery's state; nil when the device has no battery.
type BatteryInfo struct {
	Present      bool `json:"present"`
	CapacityPct  int  `json:"capacity_pct,omitempty"`  // current charge %, 0-100
	HealthPct    int  `json:"health_pct,omitempty"`    // full/design charge %, 0-100 (wear indicator)
}

// DiskInfo is one block device.
type DiskInfo struct {
	Name       string `json:"name"`
	SizeBytes  int64  `json:"size_bytes,omitempty"`
	Model      string `json:"model,omitempty"`
	Rotational bool   `json:"rotational,omitempty"`
	Transport  string `json:"transport,omitempty"` // sata, nvme, usb...
	LUKS       bool   `json:"luks,omitempty"`      // whether this device (or a child) is LUKS-encrypted
}

// GPUInfo is one graphics device.
type GPUInfo struct {
	Vendor string `json:"vendor,omitempty"` // PCI vendor id (hex, e.g. "10de")
	Device string `json:"device,omitempty"` // PCI device id (hex)
	Name   string `json:"name,omitempty"`   // human description when resolvable
}

// NetworkInfo holds network interfaces and resolver config.
type NetworkInfo struct {
	Interfaces     []NetInterface `json:"interfaces,omitempty"`
	DefaultGateway string         `json:"default_gateway,omitempty"`
	DNSServers     []string       `json:"dns_servers,omitempty"`
	PrimaryIPv4    string         `json:"primary_ipv4,omitempty"` // address on the default-route interface
	PrimaryMAC     string         `json:"primary_mac,omitempty"`
}

// NetInterface is one network interface.
type NetInterface struct {
	Name  string   `json:"name"`
	MAC   string   `json:"mac,omitempty"`
	State string   `json:"state,omitempty"` // up, down...
	IPv4  []string `json:"ipv4,omitempty"`
	IPv6  []string `json:"ipv6,omitempty"`
}

// SoftwareInfo holds the software facts: scalar counts plus the large lists that go to tables.
type SoftwareInfo struct {
	PackageCount int                   `json:"package_count,omitempty"`
	Packages     []InventoryPackage    `json:"packages,omitempty"`
	KernelModules []string             `json:"kernel_modules,omitempty"`
	Listening    []ListeningSocket     `json:"listening,omitempty"`
	LocalAccounts []LocalAccount       `json:"local_accounts,omitempty"`
	CACerts      []CACertificate       `json:"ca_certs,omitempty"`
	USBDevices   []USBDevice           `json:"usb_devices,omitempty"`
}

// InventoryPackage is one installed package with the enrichment the packages table stores.
type InventoryPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	Architecture string `json:"arch,omitempty"`
	Origin       string `json:"origin,omitempty"`       // repository/origin, e.g. "Debian"
	InstallTime  string `json:"install_time,omitempty"` // RFC 3339 when known, else ""
}

// ListeningSocket is one listening TCP/UDP socket.
type ListeningSocket struct {
	Protocol    string `json:"proto"` // tcp, tcp6, udp, udp6
	Port        int    `json:"port"`
	Address     string `json:"addr,omitempty"`
	ProcessName string `json:"proc,omitempty"`
}

// LocalAccount is one local login account (UID >= 1000), never a password hash.
type LocalAccount struct {
	Username string `json:"username"`
	UID      int    `json:"uid"`
	IsSudo   bool   `json:"sudo,omitempty"`   // in the sudo or admin group
	Shell    string `json:"shell,omitempty"`
}

// CACertificate is one certificate in the system trust store (metadata only).
type CACertificate struct {
	Subject string `json:"subject"`
	Expiry  string `json:"expiry,omitempty"` // RFC 3339
	SHA256  string `json:"sha256,omitempty"`
}

// USBDevice is one connected USB device.
type USBDevice struct {
	VendorID  string `json:"vendor"`  // 4 hex
	ProductID string `json:"product"` // 4 hex
	Name      string `json:"name,omitempty"`
}

// SecurityInfo holds detected security posture facts.
type SecurityInfo struct {
	// Products reports each security product from the fixed catalogue
	// (internal/inventory/security.go SecurityProductNames) and whether it is
	// installed and running. Only known names appear; the agent never free-forms a name.
	Products       []SecurityProduct `json:"products,omitempty"`
	FirewallActive bool              `json:"firewall_active,omitempty"` // nft ruleset present
	AuditdRunning  bool              `json:"auditd_running,omitempty"`
	USBGuardRunning bool             `json:"usbguard_running,omitempty"`
}

// SecurityProduct is the detected state of one named security product.
type SecurityProduct struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
}

// InventoryChange is one field-level inventory change recorded in history, shown on the
// device page.
type InventoryChange struct {
	Category   string    `json:"category"`    // attr, package, listening, account, module, cacert, usb
	Key        string    `json:"key"`         // the field / entry that changed
	ChangeType string    `json:"change_type"` // added, removed, modified
	OldValue   string    `json:"old_value,omitempty"`
	NewValue   string    `json:"new_value,omitempty"`
	ChangedAt  time.Time `json:"changed_at"`
}
