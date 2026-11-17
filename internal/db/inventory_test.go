package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func newInvDevice(t *testing.T, repo *db.Repository, tags ...string) *types.Device {
	t.Helper()
	ctx := context.Background()
	hw := "inv-" + time.Now().Format("150405.000000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, hw)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) > 0 {
		updated, err := repo.UpdateDeviceTags(ctx, dev.ID, tags)
		if err != nil {
			t.Fatalf("set tags: %v", err)
		}
		dev = updated
	}
	return dev
}

func sampleReport() *types.InventoryReport {
	return &types.InventoryReport{
		CollectedAt: time.Now().UTC().Truncate(time.Second),
		HW: types.HardwareInfo{
			CPUModel: "Intel i7", CPUCores: 4, CPUThreads: 8, MemoryMB: 16000,
			BIOSVersion: "1.2.3", TPMPresent: true, TPMVersion: "2.0",
			Disks: []types.DiskInfo{{Name: "nvme0n1", LUKS: true, SizeBytes: 512000000000}},
			GPUs:  []types.GPUInfo{{Vendor: "8086", Name: "Intel"}},
		},
		Net: types.NetworkInfo{
			PrimaryIPv4: "10.0.0.5", DefaultGateway: "10.0.0.1",
			DNSServers: []string{"10.0.0.1"},
			Interfaces: []types.NetInterface{{Name: "eth0", MAC: "aa:bb", State: "up", IPv4: []string{"10.0.0.5"}}},
		},
		SW: types.SoftwareInfo{
			PackageCount: 2,
			Packages:     []types.InventoryPackage{{Name: "openssl", Version: "3.0", Architecture: "amd64", Origin: "Debian"}, {Name: "bash", Version: "5.2"}},
			KernelModules: []string{"nvme", "kvm"},
			Listening:    []types.ListeningSocket{{Protocol: "tcp", Port: 22, ProcessName: "sshd"}},
			LocalAccounts: []types.LocalAccount{{Username: "jdoe", UID: 1000, IsSudo: true}},
			USBDevices:   []types.USBDevice{{VendorID: "046d", ProductID: "c52b", Name: "Logitech"}},
			CACerts:      []types.CACertificate{{SHA256: "abc123", Subject: "CN=Test"}},
		},
		Sec: types.SecurityInfo{
			FirewallActive: true, AuditdRunning: true,
			Products: []types.SecurityProduct{{Name: "clamav", Installed: true, Running: true}},
		},
	}
}

func TestInventory_FlattenStoreAndRead(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	dev := newInvDevice(t, repo)

	clean, warnings := db.SanitizeInventoryReport(sampleReport())
	if warnings != 0 {
		t.Fatalf("clean report should produce no warnings, got %d", warnings)
	}
	if err := repo.StoreInventoryReport(ctx, dev.ID, clean); err != nil {
		t.Fatalf("store: %v", err)
	}

	inv, err := repo.GetDeviceInventory(ctx, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !inv.HasInventory {
		t.Fatal("HasInventory should be true after a report")
	}
	// Scalar facts flattened to attributes.
	attrs := map[string]string{}
	for _, a := range inv.Attributes {
		attrs[a.Key] = string(a.Value)
	}
	if attrs[db.KeyHWMemoryMB] != "16000" {
		t.Errorf("hw.memory_mb = %q", attrs[db.KeyHWMemoryMB])
	}
	if attrs[db.KeyHWTPMPresent] != "true" {
		t.Errorf("hw.tpm.present = %q", attrs[db.KeyHWTPMPresent])
	}
	if attrs[db.KeyHWDiskEncrypted] != "true" {
		t.Errorf("hw.disk.encrypted_all = %q", attrs[db.KeyHWDiskEncrypted])
	}
	if attrs[db.KeyNetPrimaryIPv4] != `"10.0.0.5"` {
		t.Errorf("net.primary_ipv4 = %q", attrs[db.KeyNetPrimaryIPv4])
	}
	if attrs[db.KeySecFirewallActive] != "true" {
		t.Errorf("sec.firewall_active = %q", attrs[db.KeySecFirewallActive])
	}
	// List tables populated.
	if len(inv.Packages) != 2 || len(inv.Listening) != 1 || len(inv.Accounts) != 1 || len(inv.USBDevices) != 1 || len(inv.CACerts) != 1 || len(inv.Modules) != 2 {
		t.Errorf("list tables: pkgs=%d listen=%d acct=%d usb=%d ca=%d mod=%d",
			len(inv.Packages), len(inv.Listening), len(inv.Accounts), len(inv.USBDevices), len(inv.CACerts), len(inv.Modules))
	}
}

func TestInventory_OldAgentNoInventory(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	dev := newInvDevice(t, repo)

	// A device that never reported inventory: GetDeviceInventory must not error and
	// HasInventory must be false ("no inventory reported").
	inv, err := repo.GetDeviceInventory(ctx, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if inv.HasInventory {
		t.Fatal("HasInventory must be false for a device with no report")
	}
	// Storing a nil report is a no-op and must not error.
	if err := repo.StoreInventoryReport(ctx, dev.ID, nil); err != nil {
		t.Fatalf("nil report store: %v", err)
	}
}

func TestInventory_ChangeHistory(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	dev := newInvDevice(t, repo)

	// First report establishes a baseline. The first report records "added" for every new
	// attribute and list entry.
	r1, _ := db.SanitizeInventoryReport(sampleReport())
	if err := repo.StoreInventoryReport(ctx, dev.ID, r1); err != nil {
		t.Fatal(err)
	}

	// Second report: memory changes (modified), a NEW listening port 443 (added), the ssh
	// port removed (removed), and a new sudo account.
	r2src := sampleReport()
	r2src.HW.MemoryMB = 32000
	r2src.SW.Listening = []types.ListeningSocket{{Protocol: "tcp", Port: 443, ProcessName: "nginx"}}
	r2src.SW.LocalAccounts = []types.LocalAccount{
		{Username: "jdoe", UID: 1000, IsSudo: true},
		{Username: "attacker", UID: 1001, IsSudo: true},
	}
	r2, _ := db.SanitizeInventoryReport(r2src)
	if err := repo.StoreInventoryReport(ctx, dev.ID, r2); err != nil {
		t.Fatal(err)
	}

	changes := repo.ListInventoryChanges(ctx, dev.ID, 500)
	var sawMemMod, sawPortAdd, sawPortRemove, sawAdminAdd bool
	for _, c := range changes {
		switch {
		case c.Category == "attr" && c.Key == db.KeyHWMemoryMB && c.ChangeType == "modified":
			sawMemMod = true
		case c.Category == "listening" && c.ChangeType == "added" && contains(c.Key, "443"):
			sawPortAdd = true
		case c.Category == "listening" && c.ChangeType == "removed" && contains(c.Key, "22"):
			sawPortRemove = true
		case c.Category == "account" && c.ChangeType == "added" && contains(c.Key, "attacker"):
			sawAdminAdd = true
		}
	}
	if !sawMemMod || !sawPortAdd || !sawPortRemove || !sawAdminAdd {
		t.Fatalf("missing change: memMod=%v portAdd=%v portRemove=%v adminAdd=%v\nall=%+v",
			sawMemMod, sawPortAdd, sawPortRemove, sawAdminAdd, changes)
	}
}

func TestInventory_ChangeHistoryBounded(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	dev := newInvDevice(t, repo)

	// Churn a scalar attribute many more times than the 500-row bound.
	for i := 0; i < 700; i++ {
		src := &types.InventoryReport{CollectedAt: time.Now().UTC(), HW: types.HardwareInfo{MemoryMB: int64(1000 + i)}}
		clean, _ := db.SanitizeInventoryReport(src)
		if err := repo.StoreInventoryReport(ctx, dev.ID, clean); err != nil {
			t.Fatal(err)
		}
	}
	changes := repo.ListInventoryChanges(ctx, dev.ID, 10000)
	if len(changes) > 500 {
		t.Fatalf("history not bounded: %d rows (> 500)", len(changes))
	}
}

func TestInventory_SanitizeDropsMalformedAndOversized(t *testing.T) {
	// Oversized string is capped; invalid list entries dropped; counts flagged as warnings.
	rep := &types.InventoryReport{
		HW: types.HardwareInfo{CPUModel: string(make([]byte, 5000))},
		SW: types.SoftwareInfo{
			Packages: []types.InventoryPackage{
				{Name: "ok"},
				{Name: ""},       // dropped: empty name
				{Name: "ok"},     // dropped: duplicate
			},
			Listening: []types.ListeningSocket{
				{Protocol: "tcp", Port: 22, ProcessName: "sshd"},
				{Protocol: "tcp", Port: 0},       // dropped: bad port
				{Protocol: "tcp", Port: 70000},   // dropped: out of range
			},
		},
	}
	clean, warnings := db.SanitizeInventoryReport(rep)
	if warnings == 0 {
		t.Fatal("expected parse warnings")
	}
	if len(clean.HW.CPUModel) > 1024 {
		t.Errorf("cpu model not capped: %d", len(clean.HW.CPUModel))
	}
	if len(clean.SW.Packages) != 1 {
		t.Errorf("packages = %d, want 1 (empty + dup dropped)", len(clean.SW.Packages))
	}
	if len(clean.SW.Listening) != 1 {
		t.Errorf("listening = %d, want 1 (bad ports dropped)", len(clean.SW.Listening))
	}
}

func TestInventory_SearchAndExportTagScoping(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	// Two devices: one tagged "hr", one tagged "eng", both with 16000 MB memory and openssl.
	devHR := newInvDevice(t, repo, "hr")
	devENG := newInvDevice(t, repo, "eng")
	for _, d := range []*types.Device{devHR, devENG} {
		clean, _ := db.SanitizeInventoryReport(sampleReport())
		if err := repo.StoreInventoryReport(ctx, d.ID, clean); err != nil {
			t.Fatal(err)
		}
	}

	params := db.InventorySearchParams{
		AttrFilters: []db.InventoryFilter{{Key: db.KeyHWMemoryMB, Op: "ge", Value: "8000"}},
		PackageName: "openssl",
	}

	// Unscoped: both devices match.
	all, err := repo.SearchInventory(ctx, params, db.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 2 {
		t.Fatalf("unscoped search should see both devices, got %d", len(all))
	}

	// Scoped to "hr": only the HR device, never the eng device.
	scope := db.DeviceScope{Scoped: true, Tags: []string{"hr"}, Actor: "op"}
	scoped, err := repo.SearchInventory(ctx, params, scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range scoped {
		if r.DeviceID == devENG.ID {
			t.Fatalf("scoped operator must not see eng device %s", devENG.ID)
		}
	}
	foundHR := false
	for _, r := range scoped {
		if r.DeviceID == devHR.ID {
			foundHR = true
		}
	}
	if !foundHR {
		t.Fatal("scoped operator should see their own hr device")
	}
}

func TestInventory_SearchRejectsBadOperator(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	// A bad operator / malformed key is refused rather than injected into SQL.
	_, err := repo.SearchInventoryDeviceIDs(ctx, db.InventorySearchParams{
		AttrFilters: []db.InventoryFilter{{Key: db.KeyHWMemoryMB, Op: "; DROP TABLE devices;--", Value: "1"}},
	}, db.Unscoped)
	if err == nil {
		t.Fatal("malformed operator must be refused")
	}
	_, err = repo.SearchInventoryDeviceIDs(ctx, db.InventorySearchParams{
		AttrFilters: []db.InventoryFilter{{Key: "Bad Key!", Op: "eq", Value: "1"}},
	}, db.Unscoped)
	if err == nil {
		t.Fatal("malformed attribute key must be refused")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
