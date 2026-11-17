package db

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// maxInventoryChangesPerDevice bounds the per-device change history. After each report the
// writer trims to the most recent N rows so the table never grows without limit.
const maxInventoryChangesPerDevice = 500

// StoreInventoryReport persists a sanitized inventory report for one device: it flattens
// scalar facts to device_attributes (source "inventory"), replaces the per-device list
// tables, and records field-level change history (bounded). It computes changes by diffing
// the freshly reported state against what is already stored, BEFORE overwriting, so a change
// row is emitted exactly once per real change.
//
// It is best-effort telemetry: individual steps log and continue on error, but a hard DB
// failure on the attribute write is returned so the caller can log it. Nothing here fails a
// check-in. rep must already be sanitized (see SanitizeInventoryReport).
func (r *Repository) StoreInventoryReport(ctx context.Context, deviceID string, rep *types.InventoryReport) error {
	if rep == nil {
		return nil
	}

	// 1. Diff scalars against currently stored inventory attributes for change history.
	oldAttrs, _ := r.inventoryAttrMap(ctx, deviceID)
	newAttrs := FlattenInventoryAttributes(rep)
	attrChanges := diffAttrs(oldAttrs, newAttrs)

	// 2. Diff list tables (added/removed) BEFORE replacing them.
	listChanges := r.diffLists(ctx, deviceID, rep)

	// 3. Replace attributes (source "inventory" owns its keys only).
	if _, err := r.ReplaceDeviceAttributes(ctx, deviceID, types.AttrSourceInventory, newAttrs); err != nil {
		return fmt.Errorf("store inventory attributes: %w", err)
	}

	// 4. Replace list tables.
	r.replaceInventoryLists(ctx, deviceID, rep)

	// 5. Record change history (bounded). Best-effort.
	all := append(attrChanges, listChanges...)
	if len(all) > 0 {
		r.recordInventoryChanges(ctx, deviceID, all)
	}
	return nil
}

// invChange is one field-level inventory change.
type invChange struct {
	Category   string
	Key        string
	ChangeType string // added | removed | modified
	OldValue   string
	NewValue   string
}

func (r *Repository) inventoryAttrMap(ctx context.Context, deviceID string) (map[string]string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT key, value::text FROM device_attributes
		WHERE device_id = $1 AND source = $2`, deviceID, types.AttrSourceInventory)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// diffAttrs compares the stored attribute value text to the new attributes and yields
// added/removed/modified changes. Values are the JSON encodings (stable for scalars).
func diffAttrs(old map[string]string, newAttrs []types.DeviceAttribute) []invChange {
	var changes []invChange
	newMap := make(map[string]string, len(newAttrs))
	for _, a := range newAttrs {
		newMap[a.Key] = string(a.Value)
	}
	for k, nv := range newMap {
		ov, had := old[k]
		if !had {
			changes = append(changes, invChange{Category: "attr", Key: k, ChangeType: "added", NewValue: nv})
		} else if normJSON(ov) != normJSON(nv) {
			changes = append(changes, invChange{Category: "attr", Key: k, ChangeType: "modified", OldValue: ov, NewValue: nv})
		}
	}
	for k, ov := range old {
		if _, ok := newMap[k]; !ok {
			changes = append(changes, invChange{Category: "attr", Key: k, ChangeType: "removed", OldValue: ov})
		}
	}
	return changes
}

// normJSON strips insignificant whitespace so "16384" and " 16384 " compare equal. pgx
// returns jsonb as compact text already, but stored vs freshly-marshalled can differ in
// spacing, so trim defensively.
func normJSON(s string) string { return strings.TrimSpace(s) }

// diffLists computes added/removed entries for each list table by comparing the stored key
// set to the reported key set. Only membership changes are recorded (not field tweaks of an
// existing entry) to keep the history focused on the review-relevant events: a NEW listening
// port, a NEW local admin, a package install/removal.
func (r *Repository) diffLists(ctx context.Context, deviceID string, rep *types.InventoryReport) []invChange {
	var changes []invChange

	changes = append(changes, r.diffKeySet(ctx, deviceID, "package",
		`SELECT name FROM device_inventory_packages WHERE device_id = $1`,
		packageKeys(rep.SW.Packages))...)

	changes = append(changes, r.diffKeySet(ctx, deviceID, "listening",
		`SELECT protocol || '/' || port::text || ' ' || process_name FROM device_inventory_listening WHERE device_id = $1`,
		listeningKeys(rep.SW.Listening))...)

	changes = append(changes, r.diffKeySet(ctx, deviceID, "account",
		`SELECT username || CASE WHEN is_sudo THEN ' (sudo)' ELSE '' END FROM device_inventory_accounts WHERE device_id = $1`,
		accountKeys(rep.SW.LocalAccounts))...)

	changes = append(changes, r.diffKeySet(ctx, deviceID, "usb",
		`SELECT vendor_id || ':' || product_id FROM device_inventory_usb WHERE device_id = $1`,
		usbKeys(rep.SW.USBDevices))...)

	return changes
}

// diffKeySet runs a query returning the stored keys and diffs them against newKeys.
func (r *Repository) diffKeySet(ctx context.Context, deviceID, category, query string, newKeys map[string]struct{}) []invChange {
	rows, err := r.pool.Query(ctx, query, deviceID)
	if err != nil {
		return nil
	}
	oldKeys := map[string]struct{}{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err == nil {
			oldKeys[k] = struct{}{}
		}
	}
	rows.Close()

	var changes []invChange
	for k := range newKeys {
		if _, ok := oldKeys[k]; !ok {
			changes = append(changes, invChange{Category: category, Key: k, ChangeType: "added", NewValue: k})
		}
	}
	for k := range oldKeys {
		if _, ok := newKeys[k]; !ok {
			changes = append(changes, invChange{Category: category, Key: k, ChangeType: "removed", OldValue: k})
		}
	}
	return changes
}

func packageKeys(pkgs []types.InventoryPackage) map[string]struct{} {
	m := make(map[string]struct{}, len(pkgs))
	for _, p := range pkgs {
		m[p.Name] = struct{}{}
	}
	return m
}

func listeningKeys(ls []types.ListeningSocket) map[string]struct{} {
	m := make(map[string]struct{}, len(ls))
	for _, s := range ls {
		m[fmt.Sprintf("%s/%d %s", s.Protocol, s.Port, s.ProcessName)] = struct{}{}
	}
	return m
}

func accountKeys(as []types.LocalAccount) map[string]struct{} {
	m := make(map[string]struct{}, len(as))
	for _, a := range as {
		k := a.Username
		if a.IsSudo {
			k += " (sudo)"
		}
		m[k] = struct{}{}
	}
	return m
}

func usbKeys(ds []types.USBDevice) map[string]struct{} {
	m := make(map[string]struct{}, len(ds))
	for _, d := range ds {
		m[d.VendorID+":"+d.ProductID] = struct{}{}
	}
	return m
}

// replaceInventoryLists replaces each per-device list table with the reported set, inside one
// transaction so a reader never sees a half-replaced list. Best-effort: on error it logs via
// the returned error being discarded by the caller, but it does not panic.
func (r *Repository) replaceInventoryLists(ctx context.Context, deviceID string, rep *types.InventoryReport) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)

	tables := []string{
		"device_inventory_packages", "device_inventory_modules", "device_inventory_listening",
		"device_inventory_accounts", "device_inventory_cacerts", "device_inventory_usb",
	}
	for _, t := range tables {
		if _, err := tx.Exec(ctx, "DELETE FROM "+t+" WHERE device_id = $1", deviceID); err != nil {
			return
		}
	}

	for _, p := range rep.SW.Packages {
		var it *time.Time
		if t, err := time.Parse(time.RFC3339, p.InstallTime); err == nil {
			it = &t
		}
		if _, err := tx.Exec(ctx, `INSERT INTO device_inventory_packages
			(device_id, name, version, architecture, origin, install_time)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			deviceID, p.Name, p.Version, p.Architecture, p.Origin, it); err != nil {
			return
		}
	}
	for _, m := range rep.SW.KernelModules {
		if _, err := tx.Exec(ctx, `INSERT INTO device_inventory_modules (device_id, name)
			VALUES ($1,$2) ON CONFLICT DO NOTHING`, deviceID, m); err != nil {
			return
		}
	}
	for _, s := range rep.SW.Listening {
		if _, err := tx.Exec(ctx, `INSERT INTO device_inventory_listening
			(device_id, protocol, port, address, process_name) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT DO NOTHING`,
			deviceID, s.Protocol, s.Port, s.Address, s.ProcessName); err != nil {
			return
		}
	}
	for _, a := range rep.SW.LocalAccounts {
		if _, err := tx.Exec(ctx, `INSERT INTO device_inventory_accounts
			(device_id, username, uid, is_sudo, shell) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT DO NOTHING`,
			deviceID, a.Username, a.UID, a.IsSudo, a.Shell); err != nil {
			return
		}
	}
	for _, c := range rep.SW.CACerts {
		var exp *time.Time
		if t, err := time.Parse(time.RFC3339, c.Expiry); err == nil {
			exp = &t
		}
		if _, err := tx.Exec(ctx, `INSERT INTO device_inventory_cacerts
			(device_id, sha256, subject, expiry) VALUES ($1,$2,$3,$4)
			ON CONFLICT DO NOTHING`,
			deviceID, c.SHA256, c.Subject, exp); err != nil {
			return
		}
	}
	for _, d := range rep.SW.USBDevices {
		if _, err := tx.Exec(ctx, `INSERT INTO device_inventory_usb
			(device_id, vendor_id, product_id, name) VALUES ($1,$2,$3,$4)
			ON CONFLICT DO NOTHING`,
			deviceID, d.VendorID, d.ProductID, d.Name); err != nil {
			return
		}
	}
	_ = tx.Commit(ctx)
}

// recordInventoryChanges appends change rows and trims history to the most recent
// maxInventoryChangesPerDevice for the device. Best-effort.
func (r *Repository) recordInventoryChanges(ctx context.Context, deviceID string, changes []invChange) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	for _, c := range changes {
		if _, err := tx.Exec(ctx, `INSERT INTO device_inventory_changes
			(device_id, category, change_key, change_type, old_value, new_value, changed_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			deviceID, c.Category, truncAttr(c.Key), c.ChangeType, truncAttr(c.OldValue), truncAttr(c.NewValue), now); err != nil {
			return
		}
	}
	// Trim to the most recent N rows for this device.
	if _, err := tx.Exec(ctx, `
		DELETE FROM device_inventory_changes
		WHERE device_id = $1 AND id NOT IN (
			SELECT id FROM device_inventory_changes
			WHERE device_id = $1 ORDER BY changed_at DESC, id DESC LIMIT $2
		)`, deviceID, maxInventoryChangesPerDevice); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

// ---- Device-page read model ----

// DeviceInventory is the full inventory view for one device's detail page.
type DeviceInventory struct {
	HasInventory bool
	CollectedAt  *time.Time
	Attributes   []types.DeviceAttribute
	Packages     []types.InventoryPackage
	Modules      []string
	Listening    []types.ListeningSocket
	Accounts     []types.LocalAccount
	CACerts      []types.CACertificate
	USBDevices   []types.USBDevice
	Changes      []types.InventoryChange
}

// GetDeviceInventory assembles the inventory view for a device. HasInventory is false when
// the device has never reported inventory (old agent / pre-feature enrolment), so the page
// shows "no inventory reported".
func (r *Repository) GetDeviceInventory(ctx context.Context, deviceID string) (*DeviceInventory, error) {
	inv := &DeviceInventory{}

	attrs, err := r.GetDeviceAttributes(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	for _, a := range attrs {
		if a.Source == types.AttrSourceInventory {
			inv.Attributes = append(inv.Attributes, a)
			if a.Key == KeyInvAt {
				if t, err := time.Parse(time.RFC3339, strings.Trim(string(a.Value), `"`)); err == nil {
					ut := t.UTC()
					inv.CollectedAt = &ut
				}
			}
		}
	}
	inv.HasInventory = len(inv.Attributes) > 0

	inv.Packages = r.listInventoryPackages(ctx, deviceID, "", 0)
	inv.Modules = r.listInventoryModules(ctx, deviceID)
	inv.Listening = r.listInventoryListening(ctx, deviceID)
	inv.Accounts = r.listInventoryAccounts(ctx, deviceID)
	inv.CACerts = r.listInventoryCACerts(ctx, deviceID)
	inv.USBDevices = r.listInventoryUSB(ctx, deviceID)
	inv.Changes = r.ListInventoryChanges(ctx, deviceID, 100)

	if !inv.HasInventory && (len(inv.Packages) > 0 || len(inv.Listening) > 0) {
		inv.HasInventory = true
	}
	return inv, nil
}

func (r *Repository) listInventoryPackages(ctx context.Context, deviceID, nameFilter string, limit int) []types.InventoryPackage {
	q := `SELECT name, version, architecture, origin, COALESCE(install_time::text, '')
		FROM device_inventory_packages WHERE device_id = $1`
	args := []any{deviceID}
	if strings.TrimSpace(nameFilter) != "" {
		q += " AND name ILIKE $2"
		args = append(args, "%"+strings.TrimSpace(nameFilter)+"%")
	}
	q += " ORDER BY name"
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []types.InventoryPackage
	for rows.Next() {
		var p types.InventoryPackage
		if err := rows.Scan(&p.Name, &p.Version, &p.Architecture, &p.Origin, &p.InstallTime); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func (r *Repository) listInventoryModules(ctx context.Context, deviceID string) []string {
	rows, err := r.pool.Query(ctx, `SELECT name FROM device_inventory_modules WHERE device_id = $1 ORDER BY name`, deviceID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func (r *Repository) listInventoryListening(ctx context.Context, deviceID string) []types.ListeningSocket {
	rows, err := r.pool.Query(ctx, `SELECT protocol, port, address, process_name
		FROM device_inventory_listening WHERE device_id = $1 ORDER BY port, protocol`, deviceID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []types.ListeningSocket
	for rows.Next() {
		var s types.ListeningSocket
		if err := rows.Scan(&s.Protocol, &s.Port, &s.Address, &s.ProcessName); err == nil {
			out = append(out, s)
		}
	}
	return out
}

func (r *Repository) listInventoryAccounts(ctx context.Context, deviceID string) []types.LocalAccount {
	rows, err := r.pool.Query(ctx, `SELECT username, uid, is_sudo, shell
		FROM device_inventory_accounts WHERE device_id = $1 ORDER BY uid`, deviceID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []types.LocalAccount
	for rows.Next() {
		var a types.LocalAccount
		if err := rows.Scan(&a.Username, &a.UID, &a.IsSudo, &a.Shell); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func (r *Repository) listInventoryCACerts(ctx context.Context, deviceID string) []types.CACertificate {
	rows, err := r.pool.Query(ctx, `SELECT sha256, subject, COALESCE(expiry::text, '')
		FROM device_inventory_cacerts WHERE device_id = $1 ORDER BY expiry NULLS LAST`, deviceID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []types.CACertificate
	for rows.Next() {
		var c types.CACertificate
		if err := rows.Scan(&c.SHA256, &c.Subject, &c.Expiry); err == nil {
			out = append(out, c)
		}
	}
	return out
}

func (r *Repository) listInventoryUSB(ctx context.Context, deviceID string) []types.USBDevice {
	rows, err := r.pool.Query(ctx, `SELECT vendor_id, product_id, name
		FROM device_inventory_usb WHERE device_id = $1 ORDER BY vendor_id, product_id`, deviceID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []types.USBDevice
	for rows.Next() {
		var d types.USBDevice
		if err := rows.Scan(&d.VendorID, &d.ProductID, &d.Name); err == nil {
			out = append(out, d)
		}
	}
	return out
}

// ListInventoryChanges returns the most recent change-history rows for a device.
func (r *Repository) ListInventoryChanges(ctx context.Context, deviceID string, limit int) []types.InventoryChange {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, `
		SELECT category, change_key, change_type, old_value, new_value, changed_at
		FROM device_inventory_changes WHERE device_id = $1
		ORDER BY changed_at DESC, id DESC LIMIT $2`, deviceID, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []types.InventoryChange
	for rows.Next() {
		var c types.InventoryChange
		if err := rows.Scan(&c.Category, &c.Key, &c.ChangeType, &c.OldValue, &c.NewValue, &c.ChangedAt); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// ---- Fleet search ----

// InventoryFilter is one attribute predicate in a fleet search.
type InventoryFilter struct {
	Key   string // attribute key, e.g. "hw.memory_mb"
	Op    string // eq, ne, gt, lt, ge, le, contains
	Value string
}

// InventorySearchParams is a fleet inventory search. Any subset may be set; they are ANDed.
type InventorySearchParams struct {
	AttrFilters   []InventoryFilter
	PackageName   string // device has a package whose name ILIKE %PackageName%
	ListeningPort int    // device has a listening socket on this port
	LocalAdmin    string // device has a sudo account with this username
}

// inventoryAttrOps is the fixed allowlist of comparison operators. SQL operator text is
// chosen from this map by key, never built from user input.
var inventoryAttrOps = map[string]string{
	"eq": "=", "ne": "<>", "gt": ">", "lt": "<", "ge": ">=", "le": "<=",
}

// SearchInventoryDeviceIDs returns the device ids matching every predicate, scoped to the
// given tags. It builds only parameterized SQL; field names come from the predicate but the
// SQL operator comes from the fixed allowlist, and attribute keys are passed as parameters.
func (r *Repository) SearchInventoryDeviceIDs(ctx context.Context, params InventorySearchParams, scope DeviceScope) ([]string, error) {
	var clauses []string
	var args []any
	argn := 1
	add := func(sql string, vals ...any) {
		clauses = append(clauses, sql)
		args = append(args, vals...)
		argn += len(vals)
	}

	for _, f := range params.AttrFilters {
		if !types.ValidAttributeKey(f.Key) {
			return nil, fmt.Errorf("invalid attribute key %q", f.Key)
		}
		if f.Op == "contains" {
			add(fmt.Sprintf(`EXISTS (SELECT 1 FROM device_attributes a
				WHERE a.device_id = d.id AND a.key = $%d AND a.value::text ILIKE $%d)`, argn, argn+1),
				f.Key, "%"+f.Value+"%")
			continue
		}
		op, ok := inventoryAttrOps[f.Op]
		if !ok {
			return nil, fmt.Errorf("invalid operator %q", f.Op)
		}
		// Numeric vs text comparison: if the value parses as a number, compare numerically on
		// integer attributes; otherwise compare the JSON text. Both sides are parameters.
		add(fmt.Sprintf(`EXISTS (SELECT 1 FROM device_attributes a
			WHERE a.device_id = d.id AND a.key = $%d AND (
				(a.value_type = 'integer' AND (a.value::text)::numeric %s $%d::numeric)
				OR (a.value_type <> 'integer' AND trim(both '"' from a.value::text) %s $%d)
			))`, argn, op, argn+1, op, argn+2),
			f.Key, f.Value, f.Value)
	}

	if strings.TrimSpace(params.PackageName) != "" {
		add(fmt.Sprintf(`EXISTS (SELECT 1 FROM device_inventory_packages p
			WHERE p.device_id = d.id AND p.name ILIKE $%d)`, argn), "%"+strings.TrimSpace(params.PackageName)+"%")
	}
	if params.ListeningPort > 0 {
		add(fmt.Sprintf(`EXISTS (SELECT 1 FROM device_inventory_listening l
			WHERE l.device_id = d.id AND l.port = $%d)`, argn), params.ListeningPort)
	}
	if strings.TrimSpace(params.LocalAdmin) != "" {
		add(fmt.Sprintf(`EXISTS (SELECT 1 FROM device_inventory_accounts ac
			WHERE ac.device_id = d.id AND ac.is_sudo AND ac.username ILIKE $%d)`, argn), "%"+strings.TrimSpace(params.LocalAdmin)+"%")
	}

	where := "TRUE"
	if len(clauses) > 0 {
		where = strings.Join(clauses, " AND ")
	}

	// Tag scope: a scoped admin only sees devices carrying one of their tags.
	scoped, tags := scope.sqlArgs()
	scopeClause := fmt.Sprintf("(NOT $%d::bool OR d.tags && $%d::text[])", argn, argn+1)
	args = append(args, scoped, tags)

	query := fmt.Sprintf(`SELECT d.id FROM devices d WHERE (%s) AND %s ORDER BY d.hostname`, where, scopeClause)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory search: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// InventorySearchResult is one row of a fleet inventory search, for display and export.
type InventorySearchResult struct {
	DeviceID    string     `json:"device_id"`
	Hostname    string     `json:"hostname"`
	Tags        []string   `json:"tags"`
	Status      string     `json:"status"`
	CPUModel    string     `json:"cpu_model,omitempty"`
	MemoryMB    int64      `json:"memory_mb,omitempty"`
	OSName      string     `json:"os_name,omitempty"`
	PrimaryIPv4 string     `json:"primary_ipv4,omitempty"`
	PackageCount int       `json:"package_count,omitempty"`
	CollectedAt *time.Time `json:"collected_at,omitempty"`
}

// SearchInventory returns display rows for the matching, tag-scoped devices.
func (r *Repository) SearchInventory(ctx context.Context, params InventorySearchParams, scope DeviceScope) ([]InventorySearchResult, error) {
	ids, err := r.SearchInventoryDeviceIDs(ctx, params, scope)
	if err != nil {
		return nil, err
	}
	results := make([]InventorySearchResult, 0, len(ids))
	for _, id := range ids {
		dev, err := r.GetDeviceByID(ctx, id)
		if err != nil || dev == nil {
			continue
		}
		res := InventorySearchResult{
			DeviceID: dev.ID, Hostname: dev.Hostname, Tags: dev.Tags, Status: string(dev.Status),
		}
		attrs, _ := r.inventoryAttrMap(ctx, id)
		res.CPUModel = unquote(attrs[KeyHWCPUModel])
		res.OSName = unquote(attrs[KeyOSName])
		res.PrimaryIPv4 = unquote(attrs[KeyNetPrimaryIPv4])
		res.MemoryMB = atoi64(attrs[KeyHWMemoryMB])
		res.PackageCount = int(atoi64(attrs[KeySWPackageCount]))
		if ca := attrs[KeyInvAt]; ca != "" {
			if t, err := time.Parse(time.RFC3339, unquote(ca)); err == nil {
				ut := t.UTC()
				res.CollectedAt = &ut
			}
		}
		results = append(results, res)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Hostname < results[j].Hostname })
	return results, nil
}

// ListInventoryAttributeKeys returns the inventory-source attribute keys in use, for the
// search UI's key dropdown.
func (r *Repository) ListInventoryAttributeKeys(ctx context.Context) ([]types.AttributeKeyInfo, error) {
	all, err := r.ListAttributeKeys(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]types.AttributeKeyInfo, 0, len(all))
	for _, k := range all {
		if k.Source == types.AttrSourceInventory {
			out = append(out, k)
		}
	}
	return out, nil
}

func unquote(s string) string { return strings.Trim(strings.TrimSpace(s), `"`) }

func atoi64(s string) int64 {
	s = unquote(s)
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int64(c-'0')
	}
	return n
}
