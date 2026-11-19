package inventory

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// collectHardware reads CPU, memory, DMI, TPM, disks, battery, GPU, monitors and virtualisation.
func (c *Collector) collectHardware(ctx context.Context) types.HardwareInfo {
	hw := types.HardwareInfo{}

	// CPU model / cores / threads from /proc/cpuinfo.
	hw.CPUModel, hw.CPUCores, hw.CPUThreads = c.cpuInfo()

	// Memory from /proc/meminfo MemTotal (kB -> MB).
	hw.MemoryMB = c.memoryMB()

	// DMI product/board/BIOS identifiers.
	dmi := c.path("/sys/class/dmi/id")
	hw.SystemVendor = readTrim(filepath.Join(dmi, "sys_vendor"))
	hw.SystemProduct = readTrim(filepath.Join(dmi, "product_name"))
	hw.SystemSerial = readTrim(filepath.Join(dmi, "product_serial"))
	hw.BoardVendor = readTrim(filepath.Join(dmi, "board_vendor"))
	hw.BoardProduct = readTrim(filepath.Join(dmi, "board_name"))
	hw.BIOSVendor = readTrim(filepath.Join(dmi, "bios_vendor"))
	hw.BIOSVersion = readTrim(filepath.Join(dmi, "bios_version"))
	hw.BIOSDate = readTrim(filepath.Join(dmi, "bios_date"))

	// TPM presence + spec version from /sys/class/tpm/tpm0.
	hw.TPMPresent, hw.TPMVersion = c.tpmInfo()

	// Virtualisation via systemd-detect-virt (best effort; "none" on bare metal).
	if out, err := c.run(ctx, "systemd-detect-virt"); err == nil {
		if v := strings.TrimSpace(out); v != "" {
			hw.Virtualization = v
		}
	} else {
		// systemd-detect-virt exits non-zero on bare metal and prints "none".
		if v := strings.TrimSpace(out); v != "" {
			hw.Virtualization = v
		}
	}

	hw.MonitorCount = c.monitorCount()
	hw.Battery = c.batteryInfo()
	hw.Disks = c.disks(ctx)
	hw.GPUs = c.gpus()
	return hw
}

func (c *Collector) cpuInfo() (model string, cores, threads int) {
	f, err := os.Open(c.path("/proc/cpuinfo"))
	if err != nil {
		return "", 0, 0
	}
	defer f.Close()
	coreIDs := map[string]struct{}{}
	physIDs := map[string]struct{}{}
	curPhys := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "model name":
			if model == "" {
				model = v
			}
		case "processor":
			threads++
		case "physical id":
			curPhys = v
			physIDs[v] = struct{}{}
		case "core id":
			coreIDs[curPhys+"/"+v] = struct{}{}
		}
	}
	cores = len(coreIDs)
	if cores == 0 {
		cores = threads // single socket, kernel without topology: fall back to logical count
	}
	return model, cores, threads
}

func (c *Collector) memoryMB() int64 {
	f, err := os.Open(c.path("/proc/meminfo"))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				return kb / 1024
			}
		}
	}
	return 0
}

func (c *Collector) tpmInfo() (present bool, version string) {
	base := c.path("/sys/class/tpm/tpm0")
	if _, err := os.Stat(base); err != nil {
		return false, ""
	}
	present = true
	// tpm_version_major is "2" on TPM 2.0; older kernels expose caps/tpm_version differently.
	if maj := readTrim(filepath.Join(base, "tpm_version_major")); maj != "" {
		switch maj {
		case "2":
			version = "2.0"
		case "1":
			version = "1.2"
		default:
			version = maj
		}
		return present, version
	}
	// device/description sometimes carries "TPM 2.0 Device".
	if desc := readTrim(filepath.Join(base, "device", "description")); strings.Contains(desc, "2.0") {
		version = "2.0"
	}
	return present, version
}

func (c *Collector) monitorCount() int {
	drm := c.path("/sys/class/drm")
	entries, err := os.ReadDir(drm)
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		// Connected outputs are card*-<CONNECTOR> dirs whose "status" reads "connected".
		if !strings.Contains(e.Name(), "-") {
			continue
		}
		if readTrim(filepath.Join(drm, e.Name(), "status")) == "connected" {
			count++
		}
	}
	return count
}

func (c *Collector) batteryInfo() *types.BatteryInfo {
	ps := c.path("/sys/class/power_supply")
	entries, err := os.ReadDir(ps)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		dir := filepath.Join(ps, e.Name())
		if readTrim(filepath.Join(dir, "type")) != "Battery" {
			continue
		}
		b := &types.BatteryInfo{Present: true}
		if cap, err := strconv.Atoi(readTrim(filepath.Join(dir, "capacity"))); err == nil {
			b.CapacityPct = clampPct(cap)
		}
		// Health = energy_full / energy_full_design (or charge_full variants) as a percent.
		full := readInt(filepath.Join(dir, "energy_full"))
		design := readInt(filepath.Join(dir, "energy_full_design"))
		if full == 0 && design == 0 {
			full = readInt(filepath.Join(dir, "charge_full"))
			design = readInt(filepath.Join(dir, "charge_full_design"))
		}
		if design > 0 && full > 0 {
			b.HealthPct = clampPct(int(full * 100 / design))
		}
		return b
	}
	return nil
}

func (c *Collector) disks(ctx context.Context) []types.DiskInfo {
	block := c.path("/sys/block")
	entries, err := os.ReadDir(block)
	if err != nil {
		return nil
	}
	// Identify LUKS-backed block devices from dm-crypt holders.
	luks := c.luksBackers()
	var disks []types.DiskInfo
	for _, e := range entries {
		name := e.Name()
		// Skip virtual/loop/ram devices; keep real disks (sd*, nvme*, vd*, mmcblk*).
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") ||
			strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "zram") {
			continue
		}
		dir := filepath.Join(block, name)
		d := types.DiskInfo{Name: name}
		if sectors := readInt(filepath.Join(dir, "size")); sectors > 0 {
			d.SizeBytes = sectors * 512 // sysfs size is in 512-byte sectors
		}
		d.Model = readTrim(filepath.Join(dir, "device", "model"))
		d.Rotational = readTrim(filepath.Join(dir, "queue", "rotational")) == "1"
		d.LUKS = luks[name]
		if strings.HasPrefix(name, "nvme") {
			d.Transport = "nvme"
		} else if strings.HasPrefix(name, "mmcblk") {
			d.Transport = "mmc"
		} else {
			d.Transport = c.diskTransport(dir)
		}
		disks = append(disks, d)
	}
	return disks
}

// luksBackers returns the set of base block device names that back (directly or via a
// partition) an active LUKS/dm-crypt mapping, read from /sys/block/dm-*/slaves and the
// dm uuid (which starts with "CRYPT-LUKS").
func (c *Collector) luksBackers() map[string]bool {
	out := map[string]bool{}
	block := c.path("/sys/block")
	entries, err := os.ReadDir(block)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "dm-") {
			continue
		}
		uuid := readTrim(filepath.Join(block, e.Name(), "dm", "uuid"))
		if !strings.HasPrefix(uuid, "CRYPT-LUKS") {
			continue
		}
		slaves, _ := os.ReadDir(filepath.Join(block, e.Name(), "slaves"))
		for _, s := range slaves {
			out[baseBlockName(s.Name())] = true
		}
	}
	return out
}

func (c *Collector) diskTransport(dir string) string {
	// /sys/block/<dev>/device is a symlink into the bus tree; its target path names the bus.
	target, err := os.Readlink(filepath.Join(dir, "device"))
	if err != nil {
		return ""
	}
	switch {
	case strings.Contains(target, "usb"):
		return "usb"
	case strings.Contains(target, "ata"):
		return "sata"
	case strings.Contains(target, "nvme"):
		return "nvme"
	}
	return ""
}

func (c *Collector) gpus() []types.GPUInfo {
	drm := c.path("/sys/class/drm")
	entries, err := os.ReadDir(drm)
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var gpus []types.GPUInfo
	for _, e := range entries {
		name := e.Name()
		// Each GPU is a cardN dir (no connector suffix).
		if !strings.HasPrefix(name, "card") || strings.Contains(name, "-") {
			continue
		}
		devDir := filepath.Join(drm, name, "device")
		vendor := strings.TrimPrefix(readTrim(filepath.Join(devDir, "vendor")), "0x")
		device := strings.TrimPrefix(readTrim(filepath.Join(devDir, "device")), "0x")
		if vendor == "" && device == "" {
			continue
		}
		key := vendor + ":" + device
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		gpus = append(gpus, types.GPUInfo{Vendor: vendor, Device: device, Name: gpuVendorName(vendor)})
	}
	return gpus
}

// gpuVendorName maps a few common PCI vendor ids to a human name; unknown ids return "".
func gpuVendorName(vendor string) string {
	switch strings.ToLower(vendor) {
	case "10de":
		return "NVIDIA"
	case "1002":
		return "AMD"
	case "8086":
		return "Intel"
	}
	return ""
}

// baseBlockName strips a partition suffix to the parent disk (sda3 -> sda, nvme0n1p2 -> nvme0n1).
func baseBlockName(part string) string {
	if strings.HasPrefix(part, "nvme") || strings.HasPrefix(part, "mmcblk") {
		if i := strings.LastIndex(part, "p"); i > 0 {
			return part[:i]
		}
		return part
	}
	return strings.TrimRight(part, "0123456789")
}

func clampPct(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// readTrim reads a small sysfs/procfs file and trims whitespace; "" on any error.
func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readInt reads a file containing a single integer; 0 on any error.
func readInt(path string) int64 {
	s := readTrim(path)
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
