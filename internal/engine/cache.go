package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

const (
	// DefaultPolicyCachePath stores the latest active policy set received from spire-server.
	DefaultPolicyCachePath = "/etc/spire/policy-cache.json"
	// DefaultPendingReportsPath stores compliance reports generated while offline awaiting server sync.
	DefaultPendingReportsPath = "/etc/spire/pending-reports.json"
)

// PolicyCache represents the on-disk cached policy payload in /etc/spire/policy-cache.json.
type PolicyCache struct {
	DeviceID        string                 `json:"device_id"`
	Status          types.DeviceStatus     `json:"status"`
	Policies        []types.AssignedPolicy `json:"policies"`
	RevokedPolicies []types.AssignedPolicy `json:"revoked_policies,omitempty"`
	CachedAt        time.Time              `json:"cached_at"`
}

// SavePolicyCache atomically writes the active policy set and server response to disk (mode 0600).
func SavePolicyCache(path string, resp *types.CheckinResponse) error {
	if resp == nil {
		return nil
	}
	if path == "" {
		path = DefaultPolicyCachePath
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	cacheObj := PolicyCache{
		DeviceID:        resp.DeviceID,
		Status:          resp.Status,
		Policies:        resp.Policies,
		RevokedPolicies: resp.RevokedPolicies,
		CachedAt:        time.Now().UTC(),
	}
	if cacheObj.Policies == nil {
		cacheObj.Policies = []types.AssignedPolicy{}
	}

	data, err := json.MarshalIndent(cacheObj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy cache: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("write temp policy cache %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename policy cache %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// LoadPolicyCache reads and deserializes /etc/spire/policy-cache.json.
func LoadPolicyCache(path string) (*PolicyCache, error) {
	if path == "" {
		path = DefaultPolicyCachePath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy cache %s: %w", path, err)
	}
	var cached PolicyCache
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, fmt.Errorf("unmarshal policy cache %s: %w", path, err)
	}
	return &cached, nil
}

// QueuePendingReports merges new compliance execution items into /etc/spire/pending-reports.json (mode 0600).
func QueuePendingReports(path string, items []types.PolicyExecutionItem) error {
	if len(items) == 0 {
		return nil
	}
	if path == "" {
		path = DefaultPendingReportsPath
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	existing, _ := LoadPendingReports(path)
	merged := MergeReports(existing, items)

	data, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pending reports: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("write temp pending reports %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename pending reports %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// LoadPendingReports reads buffered compliance reports from /etc/spire/pending-reports.json.
func LoadPendingReports(path string) ([]types.PolicyExecutionItem, error) {
	if path == "" {
		path = DefaultPendingReportsPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var items []types.PolicyExecutionItem
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("unmarshal pending reports %s: %w", path, err)
	}
	return items, nil
}

// ClearPendingReports removes the buffered compliance reports file after a successful server flush.
func ClearPendingReports(path string) error {
	if path == "" {
		path = DefaultPendingReportsPath
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// MergeReports combines buffered pending reports with newly generated reports, keeping the latest per PolicyID.
func MergeReports(pending, current []types.PolicyExecutionItem) []types.PolicyExecutionItem {
	if len(pending) == 0 {
		return current
	}
	indexByPolicyID := make(map[string]int, len(pending)+len(current))
	merged := make([]types.PolicyExecutionItem, 0, len(pending)+len(current))

	for _, item := range pending {
		if idx, exists := indexByPolicyID[item.PolicyID]; exists {
			merged[idx] = item
		} else {
			indexByPolicyID[item.PolicyID] = len(merged)
			merged = append(merged, item)
		}
	}
	for _, item := range current {
		if idx, exists := indexByPolicyID[item.PolicyID]; exists {
			merged[idx] = item
		} else {
			indexByPolicyID[item.PolicyID] = len(merged)
			merged = append(merged, item)
		}
	}
	return merged
}
