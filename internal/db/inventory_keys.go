package db

import (
	"fmt"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// Inventory attribute key catalogue. These are the FIXED keys the inventory source writes
// to device_attributes. Nothing outside this list is written as an attribute, so a search
// UI and group rules see a closed, documented vocabulary. Large lists (packages, modules,
// listening sockets, local accounts, CA certs, USB devices) are NOT attributes; they live
// in their own tables.
const (
	KeyHWCPUModel       = "hw.cpu.model"
	KeyHWCPUCores       = "hw.cpu.cores"
	KeyHWCPUThreads     = "hw.cpu.threads"
	KeyHWMemoryMB       = "hw.memory_mb"
	KeyHWSystemVendor   = "hw.system.vendor"
	KeyHWSystemProduct  = "hw.system.product"
	KeyHWSystemSerial   = "hw.system.serial"
	KeyHWBoardVendor    = "hw.board.vendor"
	KeyHWBoardProduct   = "hw.board.product"
	KeyHWBIOSVendor     = "hw.bios.vendor"
	KeyHWBIOSVersion    = "hw.bios.version"
	KeyHWBIOSDate       = "hw.bios.date"
	KeyHWTPMPresent     = "hw.tpm.present"
	KeyHWTPMVersion     = "hw.tpm.version"
	KeyHWVirt           = "hw.virtualization"
	KeyHWMonitorCount   = "hw.monitor_count"
	KeyHWBatteryPresent = "hw.battery.present"
	KeyHWBatteryPct     = "hw.battery.capacity_pct"
	KeyHWBatteryHealth  = "hw.battery.health_pct"
	KeyHWDiskCount      = "hw.disk.count"
	KeyHWDiskEncrypted  = "hw.disk.encrypted_all"
	KeyHWGPUCount       = "hw.gpu.count"

	KeyNetPrimaryIPv4    = "net.primary_ipv4"
	KeyNetPrimaryMAC     = "net.primary_mac"
	KeyNetDefaultGateway = "net.default_gateway"
	KeyNetInterfaceCount = "net.interface_count"
	KeyNetDNSServers     = "net.dns_servers" // json array

	KeySWPackageCount   = "sw.package_count"
	KeySWModuleCount    = "sw.module_count"
	KeySWListeningCount = "sw.listening_count"
	KeySWAccountCount   = "sw.account_count"
	KeySWSudoCount      = "sw.sudo_account_count"
	KeySWCACertCount    = "sw.cacert_count"
	KeySWUSBCount       = "sw.usb_count"

	KeySecFirewallActive = "sec.firewall_active"
	KeySecAuditdRunning  = "sec.auditd_running"
	KeySecUSBGuard       = "sec.usbguard_running"
	// Per-product keys are sec.product.<name>.installed / .running, built dynamically from
	// the agent's fixed catalogue (SecurityProductCatalogue). The name segment is validated
	// against that catalogue so the key space stays closed.
	KeySecProductPrefix = "sec.product."

	KeyOSName    = "os.name"
	KeyOSKernel  = "os.kernel"
	KeyInvAt     = "os.inventory_collected_at"
)

// securityProductKeyNames is the set of catalogue names allowed in a sec.product.<name> key.
// Mirrors internal/inventory.SecurityProductCatalogue; kept here so the server does not import
// the agent collector package.
var securityProductKeyNames = map[string]bool{
	"clamav": true, "wazuh_agent": true, "falcon_sensor": true, "mdatp": true,
	"elastic_agent": true, "sentinelone": true, "osquery": true,
}

// normalizeProductKey turns a product name into the key-safe segment (hyphens to underscores).
func normalizeProductKey(name string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "-", "_")
}

// FlattenInventoryAttributes turns the scalar facts of a validated report into the fixed
// attribute set written under source "inventory". Empty/zero facts are omitted so an
// unavailable field does not create a misleading attribute. The returned slice is always
// within MaxAttributesPerSet.
func FlattenInventoryAttributes(rep *types.InventoryReport) []types.DeviceAttribute {
	if rep == nil {
		return nil
	}
	var out []types.DeviceAttribute
	addStr := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			out = append(out, types.StringAttr(k, truncAttr(v)))
		}
	}
	addInt := func(k string, v int64) {
		if v != 0 {
			out = append(out, types.IntAttr(k, v))
		}
	}
	addBool := func(k string, v bool) {
		out = append(out, types.BoolAttr(k, v))
	}

	hw := rep.HW
	addStr(KeyHWCPUModel, hw.CPUModel)
	addInt(KeyHWCPUCores, int64(hw.CPUCores))
	addInt(KeyHWCPUThreads, int64(hw.CPUThreads))
	addInt(KeyHWMemoryMB, hw.MemoryMB)
	addStr(KeyHWSystemVendor, hw.SystemVendor)
	addStr(KeyHWSystemProduct, hw.SystemProduct)
	addStr(KeyHWSystemSerial, hw.SystemSerial)
	addStr(KeyHWBoardVendor, hw.BoardVendor)
	addStr(KeyHWBoardProduct, hw.BoardProduct)
	addStr(KeyHWBIOSVendor, hw.BIOSVendor)
	addStr(KeyHWBIOSVersion, hw.BIOSVersion)
	addStr(KeyHWBIOSDate, hw.BIOSDate)
	addBool(KeyHWTPMPresent, hw.TPMPresent)
	addStr(KeyHWTPMVersion, hw.TPMVersion)
	addStr(KeyHWVirt, hw.Virtualization)
	addInt(KeyHWMonitorCount, int64(hw.MonitorCount))
	if hw.Battery != nil {
		addBool(KeyHWBatteryPresent, hw.Battery.Present)
		addInt(KeyHWBatteryPct, int64(hw.Battery.CapacityPct))
		addInt(KeyHWBatteryHealth, int64(hw.Battery.HealthPct))
	}
	if len(hw.Disks) > 0 {
		addInt(KeyHWDiskCount, int64(len(hw.Disks)))
		allEnc := true
		for _, d := range hw.Disks {
			if !d.LUKS {
				allEnc = false
				break
			}
		}
		addBool(KeyHWDiskEncrypted, allEnc)
	}
	if len(hw.GPUs) > 0 {
		addInt(KeyHWGPUCount, int64(len(hw.GPUs)))
	}

	net := rep.Net
	addStr(KeyNetPrimaryIPv4, net.PrimaryIPv4)
	addStr(KeyNetPrimaryMAC, net.PrimaryMAC)
	addStr(KeyNetDefaultGateway, net.DefaultGateway)
	if len(net.Interfaces) > 0 {
		addInt(KeyNetInterfaceCount, int64(len(net.Interfaces)))
	}
	if len(net.DNSServers) > 0 {
		if a, err := types.JSONAttr(KeyNetDNSServers, net.DNSServers); err == nil && len(a.Value) <= types.MaxAttributeValue {
			out = append(out, a)
		}
	}

	sw := rep.SW
	addInt(KeySWPackageCount, int64(sw.PackageCount))
	if len(sw.KernelModules) > 0 {
		addInt(KeySWModuleCount, int64(len(sw.KernelModules)))
	}
	if len(sw.Listening) > 0 {
		addInt(KeySWListeningCount, int64(len(sw.Listening)))
	}
	if len(sw.LocalAccounts) > 0 {
		addInt(KeySWAccountCount, int64(len(sw.LocalAccounts)))
		sudo := 0
		for _, a := range sw.LocalAccounts {
			if a.IsSudo {
				sudo++
			}
		}
		addInt(KeySWSudoCount, int64(sudo))
	}
	if len(sw.CACerts) > 0 {
		addInt(KeySWCACertCount, int64(len(sw.CACerts)))
	}
	if len(sw.USBDevices) > 0 {
		addInt(KeySWUSBCount, int64(len(sw.USBDevices)))
	}

	sec := rep.Sec
	addBool(KeySecFirewallActive, sec.FirewallActive)
	addBool(KeySecAuditdRunning, sec.AuditdRunning)
	addBool(KeySecUSBGuard, sec.USBGuardRunning)
	for _, p := range sec.Products {
		seg := normalizeProductKey(p.Name)
		if !securityProductKeyNames[seg] {
			continue // closed catalogue: ignore an unknown product name
		}
		addBool(fmt.Sprintf("%s%s.installed", KeySecProductPrefix, seg), p.Installed)
		addBool(fmt.Sprintf("%s%s.running", KeySecProductPrefix, seg), p.Running)
	}

	if !rep.CollectedAt.IsZero() {
		out = append(out, types.TimeAttr(KeyInvAt, rep.CollectedAt))
	}

	// Never exceed the per-source cap; the catalogue is far smaller, but guard anyway.
	if len(out) > types.MaxAttributesPerSet {
		out = out[:types.MaxAttributesPerSet]
	}
	return out
}

// truncAttr keeps a string attribute value well under the 4 KiB JSON cap.
func truncAttr(s string) string {
	const max = 1024
	if len(s) > max {
		return s[:max]
	}
	return s
}
