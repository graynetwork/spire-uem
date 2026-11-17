package db

import (
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// Inventory input bounds. The server never trusts a count or length an agent sends: every
// string is length-capped, every list is count-capped, and malformed entries are dropped
// with a parse warning rather than failing the whole check-in (the inventory is best-effort
// telemetry; a bad field must not block policy delivery). Security-relevant storage still
// fails closed downstream (a DB error aborts the write), but a single bad list entry does not.
const (
	maxInvString      = 1024
	maxInvListEntries = 5000
	maxInvCACerts     = 1000
	maxInvInterfaces  = 64
	maxInvDisks       = 64
	maxInvGPUs        = 16
	maxInvIPsPerIface = 32
)

// SanitizeInventoryReport returns a cleaned copy of rep with every string length-capped,
// every list count-capped, and malformed entries dropped. warnings counts how many entries
// were dropped or clamped, so the caller can record a parse warning. A nil report returns
// (nil, 0).
func SanitizeInventoryReport(rep *types.InventoryReport) (clean *types.InventoryReport, warnings int) {
	if rep == nil {
		return nil, 0
	}
	w := 0
	out := &types.InventoryReport{CollectedAt: rep.CollectedAt, Truncated: rep.Truncated}

	// Hardware scalars.
	hw := rep.HW
	hw.CPUModel = cap1024(hw.CPUModel)
	hw.SystemVendor = cap1024(hw.SystemVendor)
	hw.SystemProduct = cap1024(hw.SystemProduct)
	hw.SystemSerial = cap1024(hw.SystemSerial)
	hw.BoardVendor = cap1024(hw.BoardVendor)
	hw.BoardProduct = cap1024(hw.BoardProduct)
	hw.BIOSVendor = cap1024(hw.BIOSVendor)
	hw.BIOSVersion = cap1024(hw.BIOSVersion)
	hw.BIOSDate = cap1024(hw.BIOSDate)
	hw.TPMVersion = cap1024(hw.TPMVersion)
	hw.Virtualization = cap1024(hw.Virtualization)
	hw.CPUCores = clampNonNeg(hw.CPUCores)
	hw.CPUThreads = clampNonNeg(hw.CPUThreads)
	hw.MonitorCount = clampNonNeg(hw.MonitorCount)
	if hw.MemoryMB < 0 {
		hw.MemoryMB = 0
	}
	if hw.Battery != nil {
		hw.Battery.CapacityPct = clampPctInt(hw.Battery.CapacityPct)
		hw.Battery.HealthPct = clampPctInt(hw.Battery.HealthPct)
	}
	if len(hw.Disks) > maxInvDisks {
		hw.Disks = hw.Disks[:maxInvDisks]
		out.Truncated = true
		w++
	}
	for i := range hw.Disks {
		hw.Disks[i].Name = cap1024(hw.Disks[i].Name)
		hw.Disks[i].Model = cap1024(hw.Disks[i].Model)
		hw.Disks[i].Transport = cap1024(hw.Disks[i].Transport)
		if hw.Disks[i].SizeBytes < 0 {
			hw.Disks[i].SizeBytes = 0
		}
	}
	if len(hw.GPUs) > maxInvGPUs {
		hw.GPUs = hw.GPUs[:maxInvGPUs]
		out.Truncated = true
		w++
	}
	for i := range hw.GPUs {
		hw.GPUs[i].Vendor = cap1024(hw.GPUs[i].Vendor)
		hw.GPUs[i].Device = cap1024(hw.GPUs[i].Device)
		hw.GPUs[i].Name = cap1024(hw.GPUs[i].Name)
	}
	out.HW = hw

	// Network.
	net := rep.Net
	net.DefaultGateway = cap1024(net.DefaultGateway)
	net.PrimaryIPv4 = cap1024(net.PrimaryIPv4)
	net.PrimaryMAC = cap1024(net.PrimaryMAC)
	if len(net.Interfaces) > maxInvInterfaces {
		net.Interfaces = net.Interfaces[:maxInvInterfaces]
		out.Truncated = true
		w++
	}
	for i := range net.Interfaces {
		net.Interfaces[i].Name = cap1024(net.Interfaces[i].Name)
		net.Interfaces[i].MAC = cap1024(net.Interfaces[i].MAC)
		net.Interfaces[i].State = cap1024(net.Interfaces[i].State)
		net.Interfaces[i].IPv4 = capStrList(net.Interfaces[i].IPv4, maxInvIPsPerIface, &w)
		net.Interfaces[i].IPv6 = capStrList(net.Interfaces[i].IPv6, maxInvIPsPerIface, &w)
	}
	net.DNSServers = capStrList(net.DNSServers, maxInvIPsPerIface, &w)
	out.Net = net

	// Software lists.
	sw := rep.SW
	if sw.PackageCount < 0 {
		sw.PackageCount = 0
	}
	sw.Packages, w = sanitizePackages(sw.Packages, w)
	sw.KernelModules = capStrList(sw.KernelModules, maxInvListEntries, &w)
	sw.Listening, w = sanitizeListening(sw.Listening, w)
	sw.LocalAccounts, w = sanitizeAccounts(sw.LocalAccounts, w)
	sw.CACerts, w = sanitizeCACerts(sw.CACerts, w)
	sw.USBDevices, w = sanitizeUSB(sw.USBDevices, w)
	out.SW = sw

	// Security.
	sec := rep.Sec
	for i := range sec.Products {
		sec.Products[i].Name = cap1024(sec.Products[i].Name)
	}
	out.Sec = sec

	return out, w
}

func sanitizePackages(in []types.InventoryPackage, w int) ([]types.InventoryPackage, int) {
	if len(in) > maxInvListEntries {
		in = in[:maxInvListEntries]
		w++
	}
	out := in[:0]
	seen := map[string]struct{}{}
	for _, p := range in {
		p.Name = cap1024(strings.TrimSpace(p.Name))
		if p.Name == "" {
			w++
			continue
		}
		if _, dup := seen[p.Name]; dup {
			w++
			continue // table PK is (device_id, name); drop a duplicate rather than error
		}
		seen[p.Name] = struct{}{}
		p.Version = cap1024(p.Version)
		p.Architecture = cap1024(p.Architecture)
		p.Origin = cap1024(p.Origin)
		p.InstallTime = cap1024(p.InstallTime)
		out = append(out, p)
	}
	return out, w
}

func sanitizeListening(in []types.ListeningSocket, w int) ([]types.ListeningSocket, int) {
	if len(in) > maxInvListEntries {
		in = in[:maxInvListEntries]
		w++
	}
	out := in[:0]
	seen := map[string]struct{}{}
	for _, s := range in {
		s.Protocol = cap1024(strings.TrimSpace(s.Protocol))
		s.Address = cap1024(s.Address)
		s.ProcessName = cap1024(s.ProcessName)
		if s.Protocol == "" || s.Port <= 0 || s.Port > 65535 {
			w++
			continue
		}
		key := s.Protocol + "|" + s.Address + "|" + itoa(s.Port)
		if _, dup := seen[key]; dup {
			w++
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	return out, w
}

func sanitizeAccounts(in []types.LocalAccount, w int) ([]types.LocalAccount, int) {
	if len(in) > maxInvListEntries {
		in = in[:maxInvListEntries]
		w++
	}
	out := in[:0]
	seen := map[string]struct{}{}
	for _, a := range in {
		a.Username = cap1024(strings.TrimSpace(a.Username))
		a.Shell = cap1024(a.Shell)
		if a.Username == "" || a.UID < 0 {
			w++
			continue
		}
		if _, dup := seen[a.Username]; dup {
			w++
			continue
		}
		seen[a.Username] = struct{}{}
		out = append(out, a)
	}
	return out, w
}

func sanitizeCACerts(in []types.CACertificate, w int) ([]types.CACertificate, int) {
	if len(in) > maxInvCACerts {
		in = in[:maxInvCACerts]
		w++
	}
	out := in[:0]
	seen := map[string]struct{}{}
	for _, c := range in {
		c.SHA256 = cap1024(strings.ToLower(strings.TrimSpace(c.SHA256)))
		c.Subject = cap1024(c.Subject)
		c.Expiry = cap1024(c.Expiry)
		if c.SHA256 == "" {
			w++
			continue
		}
		if _, dup := seen[c.SHA256]; dup {
			w++
			continue
		}
		seen[c.SHA256] = struct{}{}
		out = append(out, c)
	}
	return out, w
}

func sanitizeUSB(in []types.USBDevice, w int) ([]types.USBDevice, int) {
	if len(in) > maxInvListEntries {
		in = in[:maxInvListEntries]
		w++
	}
	out := in[:0]
	seen := map[string]struct{}{}
	for _, d := range in {
		d.VendorID = cap1024(strings.TrimSpace(d.VendorID))
		d.ProductID = cap1024(strings.TrimSpace(d.ProductID))
		d.Name = cap1024(d.Name)
		if d.VendorID == "" || d.ProductID == "" {
			w++
			continue
		}
		key := d.VendorID + ":" + d.ProductID + "|" + d.Name
		if _, dup := seen[key]; dup {
			w++
			continue
		}
		seen[key] = struct{}{}
		out = append(out, d)
	}
	return out, w
}

func cap1024(s string) string {
	s = strings.TrimSpace(s)
	// Strip NUL and other control bytes that could corrupt storage or logs.
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 {
			return -1
		}
		return r
	}, s)
	if len(s) > maxInvString {
		return s[:maxInvString]
	}
	return s
}

func capStrList(in []string, max int, w *int) []string {
	if len(in) > max {
		in = in[:max]
		*w++
	}
	out := in[:0]
	for _, s := range in {
		s = cap1024(s)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func clampNonNeg(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

func clampPctInt(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func itoa(n int) string {
	// small helper avoiding strconv import churn in this file
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
