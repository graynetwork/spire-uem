package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// writeFixture writes a file under root, creating parent dirs.
func writeFixture(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// fullFixtureRoot builds a realistic sysfs/procfs/etc fixture for a laptop with a TPM 2.0,
// one NVMe disk (LUKS-encrypted), a battery, an Intel GPU, one connected monitor and a NIC.
func fullFixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	// DMI.
	writeFixture(t, root, "sys/class/dmi/id/sys_vendor", "LENOVO\n")
	writeFixture(t, root, "sys/class/dmi/id/product_name", "ThinkPad X1\n")
	writeFixture(t, root, "sys/class/dmi/id/product_serial", "PF0ABCDE\n")
	writeFixture(t, root, "sys/class/dmi/id/board_vendor", "LENOVO\n")
	writeFixture(t, root, "sys/class/dmi/id/board_name", "20XYZ\n")
	writeFixture(t, root, "sys/class/dmi/id/bios_vendor", "LENOVO\n")
	writeFixture(t, root, "sys/class/dmi/id/bios_version", "N32ET\n")
	writeFixture(t, root, "sys/class/dmi/id/bios_date", "06/01/2024\n")

	// CPU + memory.
	writeFixture(t, root, "proc/cpuinfo",
		"processor\t: 0\nmodel name\t: Intel(R) Core(TM) i7-1165G7\nphysical id\t: 0\ncore id\t: 0\n\n"+
			"processor\t: 1\nmodel name\t: Intel(R) Core(TM) i7-1165G7\nphysical id\t: 0\ncore id\t: 0\n\n"+
			"processor\t: 2\nmodel name\t: Intel(R) Core(TM) i7-1165G7\nphysical id\t: 0\ncore id\t: 1\n\n"+
			"processor\t: 3\nmodel name\t: Intel(R) Core(TM) i7-1165G7\nphysical id\t: 0\ncore id\t: 1\n")
	writeFixture(t, root, "proc/meminfo", "MemTotal:       16222680 kB\nMemFree: 100 kB\n")

	// TPM 2.0.
	writeFixture(t, root, "sys/class/tpm/tpm0/tpm_version_major", "2\n")

	// Disk: nvme0n1, LUKS-backed via dm-0.
	writeFixture(t, root, "sys/block/nvme0n1/size", "1000215216\n")
	writeFixture(t, root, "sys/block/nvme0n1/device/model", "Samsung SSD 980\n")
	writeFixture(t, root, "sys/block/nvme0n1/queue/rotational", "0\n")
	writeFixture(t, root, "sys/block/dm-0/dm/uuid", "CRYPT-LUKS2-abc-root\n")
	writeFixture(t, root, "sys/block/dm-0/slaves/nvme0n1p3/.keep", "")

	// Battery at 82%, health 90%.
	writeFixture(t, root, "sys/class/power_supply/BAT0/type", "Battery\n")
	writeFixture(t, root, "sys/class/power_supply/BAT0/capacity", "82\n")
	writeFixture(t, root, "sys/class/power_supply/BAT0/energy_full", "45000000\n")
	writeFixture(t, root, "sys/class/power_supply/BAT0/energy_full_design", "50000000\n")

	// GPU (Intel) + one connected monitor.
	writeFixture(t, root, "sys/class/drm/card0/device/vendor", "0x8086\n")
	writeFixture(t, root, "sys/class/drm/card0/device/device", "0x9a49\n")
	writeFixture(t, root, "sys/class/drm/card0-eDP-1/status", "connected\n")
	writeFixture(t, root, "sys/class/drm/card0-HDMI-A-1/status", "disconnected\n")

	// Network: one interface + default route + DNS.
	writeFixture(t, root, "sys/class/net/wlan0/address", "aa:bb:cc:dd:ee:ff\n")
	writeFixture(t, root, "sys/class/net/wlan0/operstate", "up\n")
	writeFixture(t, root, "proc/net/if_inet", "wlan0\t192.168.1.50\nwlan0\tfe80::1\n")
	// Default route via 192.168.1.1 (0101A8C0 little-endian) on wlan0.
	writeFixture(t, root, "proc/net/route",
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"+
			"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n")
	writeFixture(t, root, "etc/resolv.conf", "nameserver 192.168.1.1\nnameserver 9.9.9.9\n")

	// dpkg .list mtimes for install-time (just the dir existing).
	writeFixture(t, root, "var/lib/dpkg/info/openssl.list", "/usr/bin/openssl\n")

	// USB device.
	writeFixture(t, root, "sys/bus/usb/devices/1-1/idVendor", "046d\n")
	writeFixture(t, root, "sys/bus/usb/devices/1-1/idProduct", "c52b\n")
	writeFixture(t, root, "sys/bus/usb/devices/1-1/manufacturer", "Logitech\n")
	writeFixture(t, root, "sys/bus/usb/devices/1-1/product", "USB Receiver\n")

	// Kernel modules.
	writeFixture(t, root, "proc/modules", "nvme 100000 2 - Live 0x0\nkvm 200000 0 - Live 0x0\n")

	// Local accounts + sudo group.
	writeFixture(t, root, "etc/passwd",
		"root:x:0:0:root:/root:/bin/bash\n"+
			"jdoe:x:1000:1000:John:/home/jdoe:/bin/bash\n"+
			"svc:x:999:999:svc:/var/svc:/usr/sbin/nologin\n")
	writeFixture(t, root, "etc/group", "sudo:x:27:jdoe\nusers:x:100:\n")

	return root
}

// fakeRunner returns canned command output keyed by the command name.
func fakeRunner(out map[string]string) func(ctx context.Context, name string, args ...string) (string, error) {
	return func(ctx context.Context, name string, args ...string) (string, error) {
		if v, ok := out[name]; ok {
			return v, nil
		}
		return "", nil
	}
}

func TestCollect_FullLaptop(t *testing.T) {
	root := fullFixtureRoot(t)
	c := &Collector{
		Root: root,
		Run: fakeRunner(map[string]string{
			"systemd-detect-virt": "none\n",
			"dpkg-query":          "openssl\t3.0.11-1~deb12u2\tamd64\tDebian\n",
			"ss":                  "tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\nudp   UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:((\"dhclient\",pid=2,fd=5))\n",
			"systemctl":           "active\n",
			"nft":                 "table inet filter {\n}\n",
		}),
	}
	rep := c.Collect(context.Background())

	// Hardware.
	if rep.HW.CPUModel == "" || rep.HW.CPUThreads != 4 || rep.HW.CPUCores != 2 {
		t.Errorf("cpu: model=%q cores=%d threads=%d", rep.HW.CPUModel, rep.HW.CPUCores, rep.HW.CPUThreads)
	}
	if rep.HW.MemoryMB != 16222680/1024 {
		t.Errorf("memory_mb = %d", rep.HW.MemoryMB)
	}
	if rep.HW.SystemVendor != "LENOVO" || rep.HW.BIOSVersion != "N32ET" {
		t.Errorf("dmi: %+v", rep.HW)
	}
	if !rep.HW.TPMPresent || rep.HW.TPMVersion != "2.0" {
		t.Errorf("tpm present=%v version=%q", rep.HW.TPMPresent, rep.HW.TPMVersion)
	}
	if rep.HW.Virtualization != "none" {
		t.Errorf("virt = %q", rep.HW.Virtualization)
	}
	if rep.HW.MonitorCount != 1 {
		t.Errorf("monitors = %d", rep.HW.MonitorCount)
	}
	if rep.HW.Battery == nil || rep.HW.Battery.CapacityPct != 82 || rep.HW.Battery.HealthPct != 90 {
		t.Errorf("battery = %+v", rep.HW.Battery)
	}
	if len(rep.HW.Disks) != 1 || !rep.HW.Disks[0].LUKS || rep.HW.Disks[0].Transport != "nvme" || rep.HW.Disks[0].Rotational {
		t.Errorf("disks = %+v", rep.HW.Disks)
	}
	if len(rep.HW.GPUs) != 1 || rep.HW.GPUs[0].Vendor != "8086" || rep.HW.GPUs[0].Name != "Intel" {
		t.Errorf("gpus = %+v", rep.HW.GPUs)
	}

	// Network.
	if rep.Net.DefaultGateway != "192.168.1.1" {
		t.Errorf("gateway = %q", rep.Net.DefaultGateway)
	}
	if rep.Net.PrimaryIPv4 != "192.168.1.50" {
		t.Errorf("primary ipv4 = %q", rep.Net.PrimaryIPv4)
	}
	if len(rep.Net.DNSServers) != 2 || rep.Net.DNSServers[0] != "192.168.1.1" {
		t.Errorf("dns = %v", rep.Net.DNSServers)
	}
	if len(rep.Net.Interfaces) != 1 || rep.Net.Interfaces[0].Name != "wlan0" {
		t.Errorf("interfaces = %+v", rep.Net.Interfaces)
	}

	// Software.
	if len(rep.SW.Packages) != 1 || rep.SW.Packages[0].Name != "openssl" || rep.SW.Packages[0].Architecture != "amd64" || rep.SW.Packages[0].Origin != "Debian" {
		t.Errorf("packages = %+v", rep.SW.Packages)
	}
	if rep.SW.Packages[0].InstallTime == "" {
		t.Errorf("expected install time from .list mtime")
	}
	if len(rep.SW.KernelModules) != 2 {
		t.Errorf("modules = %v", rep.SW.KernelModules)
	}
	if len(rep.SW.Listening) != 2 {
		t.Fatalf("listening = %+v", rep.SW.Listening)
	}
	gotSSH := false
	for _, s := range rep.SW.Listening {
		if s.Port == 22 && s.Protocol == "tcp" && s.ProcessName == "sshd" {
			gotSSH = true
		}
	}
	if !gotSSH {
		t.Errorf("expected sshd on 22/tcp: %+v", rep.SW.Listening)
	}
	// Only jdoe (uid 1000) qualifies; svc (999) and root (0) are excluded.
	if len(rep.SW.LocalAccounts) != 1 || rep.SW.LocalAccounts[0].Username != "jdoe" || !rep.SW.LocalAccounts[0].IsSudo {
		t.Errorf("accounts = %+v", rep.SW.LocalAccounts)
	}
	if len(rep.SW.USBDevices) != 1 || rep.SW.USBDevices[0].VendorID != "046d" {
		t.Errorf("usb = %+v", rep.SW.USBDevices)
	}

	// Security: firewall active (nft), auditd active (systemctl canned), products not installed
	// by dpkg status but systemctl returns active for everything in this fake, so running=true.
	if !rep.Sec.FirewallActive {
		t.Errorf("firewall should be active")
	}
	if !rep.Sec.AuditdRunning {
		t.Errorf("auditd should be running")
	}
	if len(rep.Sec.Products) != len(SecurityProductCatalogue) {
		t.Errorf("expected one product entry per catalogue item, got %d", len(rep.Sec.Products))
	}
}

// TestCollect_VMNoDMINoBatteryNoTPM covers a server VM: no DMI, no battery, no TPM, no GPU.
func TestCollect_VMNoDMINoBatteryNoTPM(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "proc/cpuinfo", "processor\t: 0\nmodel name\t: QEMU Virtual CPU\n")
	writeFixture(t, root, "proc/meminfo", "MemTotal:       2048000 kB\n")
	// No dmi, tpm, battery, drm, block, usb, net dirs at all.

	c := &Collector{
		Root: root,
		Run: fakeRunner(map[string]string{
			"systemd-detect-virt": "kvm\n",
		}),
	}
	rep := c.Collect(context.Background())

	if rep.HW.Virtualization != "kvm" {
		t.Errorf("virt = %q", rep.HW.Virtualization)
	}
	if rep.HW.TPMPresent {
		t.Errorf("TPM must be absent")
	}
	if rep.HW.Battery != nil {
		t.Errorf("battery must be nil on a VM")
	}
	if rep.HW.SystemVendor != "" {
		t.Errorf("no DMI expected, got vendor %q", rep.HW.SystemVendor)
	}
	if len(rep.HW.Disks) != 0 || len(rep.HW.GPUs) != 0 {
		t.Errorf("no disks/gpus expected")
	}
	if rep.HW.CPUModel == "" {
		t.Errorf("CPU model should still be read")
	}
	// A report with nothing but CPU/mem is still valid to send.
	if rep.HW.MemoryMB != 2000 {
		t.Errorf("memory = %d", rep.HW.MemoryMB)
	}
}

// TestCollect_Truncation: a small MaxList sets Truncated when a list exceeds it.
func TestCollect_Truncation(t *testing.T) {
	root := t.TempDir()
	mods := ""
	for i := 0; i < 50; i++ {
		mods += "mod" + itoaLocal(i) + " 1 0 - Live 0x0\n"
	}
	writeFixture(t, root, "proc/modules", mods)
	writeFixture(t, root, "proc/cpuinfo", "model name\t: x\nprocessor\t: 0\n")
	writeFixture(t, root, "proc/meminfo", "MemTotal: 1024 kB\n")

	c := &Collector{Root: root, MaxList: 10, Run: fakeRunner(nil)}
	rep := c.Collect(context.Background())
	if len(rep.SW.KernelModules) != 10 {
		t.Errorf("modules capped to %d, want 10", len(rep.SW.KernelModules))
	}
	if !rep.Truncated {
		t.Errorf("Truncated flag should be set when a list is clipped")
	}
}

func itoaLocal(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
