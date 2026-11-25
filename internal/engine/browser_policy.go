package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// BROWSER_POLICY engine. It sets enterprise policies for the Chromium-family browsers and
// Firefox, sharing the browser paths of BROWSER_CERTIFICATE (browser_cert.go):
//
//   - Chromium family: one managed policy file per policy, spire-policy-<id>.json, in each
//     browser's managed directory. Chrome merges every file in that directory.
//   - Firefox: one policies.json per installation, shared with BROWSER_CERTIFICATE and with
//     anything else on the host. Each top-level policy key, and each preference inside
//     "Preferences", is merged on its own. SpireUEM records what each key held before, and
//     removal restores it, but only while the key still holds what SpireUEM wrote.
//
// Two BROWSER_POLICY policies may not set the same key: the second one fails with a
// conflict instead of the outcome depending on the order they were applied in.

const (
	browserPolicyFilePrefix = "spire-policy-"
	maxBrowserPolicyKeys    = 200
	maxBrowserPolicyBytes   = 64 << 10
	firefoxPrefsKey         = "Preferences"
	firefoxPrefSlotPrefix   = "Preferences:"
)

var (
	// browserPolicyKeyRe matches Chrome and Firefox policy names, which are PascalCase
	// identifiers. It rules out paths, dots and separators by construction.
	browserPolicyKeyRe = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,99}$`)
	// firefoxPrefNameRe matches about:config preference names.
	firefoxPrefNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,199}$`)

	// Keys owned by BROWSER_CERTIFICATE. A BROWSER_POLICY may not set them, or the two
	// policies would overwrite each other.
	reservedChromiumKeys    = map[string]bool{"AutoSelectCertificateForUrls": true}
	reservedFirefoxPrefKeys = map[string]bool{firefoxPrefKey: true}
)

type browserPolicyState struct {
	Policies map[string]*browserPolicyEntry `json:"policies,omitempty"`
	// FirefoxCreated lists policies.json files SpireUEM created. Such a file is deleted
	// once it holds nothing.
	FirefoxCreated map[string]bool `json:"firefox_created,omitempty"`
}

type browserPolicyEntry struct {
	ChromiumFiles []string `json:"chromium_files,omitempty"`
	ChromiumKeys  []string `json:"chromium_keys,omitempty"`
	// Firefox maps a policies.json path to the slots this policy wrote in it. A slot is a
	// top-level policy name, or "Preferences:<pref>" for one preference.
	Firefox map[string]map[string]browserPolicySlot `json:"firefox,omitempty"`
}

type browserPolicySlot struct {
	HadPrior bool            `json:"had_prior"`
	Prior    json.RawMessage `json:"prior,omitempty"`
	Written  json.RawMessage `json:"written"`
}

func browserPolicyStatePath() string {
	return browserCertPath("var/lib/spire/browser-policy/state.json")
}

// ValidateBrowserPolicyPayload checks a BROWSER_POLICY payload before it is stored.
func ValidateBrowserPolicyPayload(p types.BrowserPolicyPayload) error {
	_, err := firefoxSlots(p.Firefox)
	if err != nil {
		return err
	}
	if len(p.Chromium) == 0 && len(p.Firefox) == 0 {
		return fmt.Errorf("set at least one chromium or firefox policy")
	}
	if len(p.Chromium) > maxBrowserPolicyKeys {
		return fmt.Errorf("at most %d chromium policies are allowed", maxBrowserPolicyKeys)
	}
	for k, v := range p.Chromium {
		if !browserPolicyKeyRe.MatchString(k) {
			return fmt.Errorf("chromium: %q is not a policy name", k)
		}
		if reservedChromiumKeys[k] {
			return fmt.Errorf("chromium: %s is set by BROWSER_CERTIFICATE policies", k)
		}
		if err := checkPolicyValue(v); err != nil {
			return fmt.Errorf("chromium.%s: %w", k, err)
		}
	}
	b, _ := json.Marshal(p)
	if len(b) > maxBrowserPolicyBytes {
		return fmt.Errorf("payload is larger than %d bytes", maxBrowserPolicyBytes)
	}
	return nil
}

func checkPolicyValue(v json.RawMessage) error {
	t := bytes.TrimSpace(v)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) || !json.Valid(t) {
		return fmt.Errorf("value must be valid, non-null JSON")
	}
	return nil
}

// firefoxSlots flattens the Firefox settings into slots, expanding "Preferences".
func firefoxSlots(ff map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	slots := map[string]json.RawMessage{}
	for k, v := range ff {
		if !browserPolicyKeyRe.MatchString(k) {
			return nil, fmt.Errorf("firefox: %q is not a policy name", k)
		}
		if k != firefoxPrefsKey {
			if err := checkPolicyValue(v); err != nil {
				return nil, fmt.Errorf("firefox.%s: %w", k, err)
			}
			slots[k] = v
			continue
		}
		var prefs map[string]json.RawMessage
		if err := json.Unmarshal(v, &prefs); err != nil || prefs == nil {
			return nil, fmt.Errorf("firefox.Preferences must be an object of preference names")
		}
		if len(prefs) == 0 {
			return nil, fmt.Errorf("firefox.Preferences is empty")
		}
		for name, pv := range prefs {
			if !firefoxPrefNameRe.MatchString(name) {
				return nil, fmt.Errorf("firefox.Preferences: %q is not a preference name", name)
			}
			if reservedFirefoxPrefKeys[name] {
				return nil, fmt.Errorf("firefox.Preferences: %s is set by BROWSER_CERTIFICATE policies", name)
			}
			if err := checkPolicyValue(pv); err != nil {
				return nil, fmt.Errorf("firefox.Preferences.%s: %w", name, err)
			}
			slots[firefoxPrefSlotPrefix+name] = pv
		}
	}
	if len(slots) > maxBrowserPolicyKeys {
		return nil, fmt.Errorf("at most %d firefox policies are allowed", maxBrowserPolicyKeys)
	}
	return slots, nil
}

func chromiumPolicyFileName(policyID string) string {
	return browserPolicyFilePrefix + policyID + ".json"
}

// EnforceBrowserPolicy applies one BROWSER_POLICY and reads it back.
func EnforceBrowserPolicy(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	_ = ctx
	id := strings.TrimSpace(policy.ID)
	if !safePolicyIDRe.MatchString(id) {
		return failItem(policy.ID, "invalid policy id", nil)
	}
	var payload types.BrowserPolicyPayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return failItem(id, fmt.Sprintf("invalid BROWSER_POLICY payload: %v", err), nil)
	}
	if err := ValidateBrowserPolicyPayload(payload); err != nil {
		return failItem(id, err.Error(), nil)
	}
	slots, _ := firefoxSlots(payload.Firefox)
	details := map[string]any{
		"policy_id": id,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	state, err := loadBrowserPolicyState()
	if err != nil {
		return failItem(id, fmt.Sprintf("read state: %v", err), details)
	}

	// Refuse a key another BROWSER_POLICY already owns, before writing anything.
	for otherID, other := range state.Policies {
		if otherID == id {
			continue
		}
		for _, k := range other.ChromiumKeys {
			if _, ok := payload.Chromium[k]; ok {
				return failItem(id, fmt.Sprintf("conflict: chromium policy %s is already set by policy %s", k, otherID), details)
			}
		}
		for _, fileSlots := range other.Firefox {
			for slot := range fileSlots {
				if _, ok := slots[slot]; ok {
					return failItem(id, fmt.Sprintf("conflict: firefox %s is already set by policy %s", slot, otherID), details)
				}
			}
		}
	}

	entry := state.Policies[id]
	if entry == nil {
		entry = &browserPolicyEntry{}
		state.Policies[id] = entry
	}

	// Chromium family.
	if len(payload.Chromium) == 0 {
		removeBrowserPolicyChromium(entry)
	} else {
		content, err := json.MarshalIndent(payload.Chromium, "", "  ")
		if err != nil {
			return failItem(id, err.Error(), details)
		}
		content = append(content, '\n')
		var written []string
		for _, rel := range chromiumManagedDirs {
			dir := browserCertPath(rel)
			path := filepath.Join(dir, chromiumPolicyFileName(id))
			if err := os.MkdirAll(dir, 0755); err != nil {
				return failItem(id, fmt.Sprintf("mkdir %s: %v", dir, err), details)
			}
			if err := atomicWriteBrowserFile(path, content, 0644); err != nil {
				return failItem(id, fmt.Sprintf("write %s: %v", path, err), details)
			}
			written = append(written, path)
		}
		entry.ChromiumFiles = written
		entry.ChromiumKeys = sortedKeys(payload.Chromium)
		details["chromium_files"] = written
	}

	// Firefox.
	if err := applyBrowserPolicyFirefox(&state, entry, slots); err != nil {
		_ = saveBrowserPolicyState(state)
		return failItem(id, err.Error(), details)
	}
	if len(entry.Firefox) > 0 {
		paths := make([]string, 0, len(entry.Firefox))
		for p := range entry.Firefox {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		details["firefox_policy_files"] = paths
	}
	if len(entry.ChromiumFiles) == 0 && len(entry.Firefox) == 0 {
		delete(state.Policies, id)
	}
	if err := saveBrowserPolicyState(state); err != nil {
		return failItem(id, fmt.Sprintf("write state: %v", err), details)
	}

	// Read back.
	if len(payload.Chromium) > 0 {
		for _, p := range entry.ChromiumFiles {
			var got map[string]json.RawMessage
			data, err := os.ReadFile(p)
			if err != nil || json.Unmarshal(data, &got) != nil || !rawMapsEqual(got, payload.Chromium) {
				return failItem(id, fmt.Sprintf("verification failed for %s", p), details)
			}
		}
	}
	for path, fileSlots := range entry.Firefox {
		cur, err := readFirefoxSlots(path)
		if err != nil {
			return failItem(id, fmt.Sprintf("verification failed for %s: %v", path, err), details)
		}
		for slot, s := range fileSlots {
			if v, ok := cur[slot]; !ok || !jsonEqual(v, s.Written) {
				return failItem(id, fmt.Sprintf("verification failed for %s (%s)", path, slot), details)
			}
		}
	}
	details["chromium_policies"] = len(payload.Chromium)
	details["firefox_policies"] = len(slots)
	return types.PolicyExecutionItem{
		PolicyID:         id,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  mustJSON(details),
	}
}

// RemoveBrowserPolicy removes exactly what EnforceBrowserPolicy wrote for one policy.
func RemoveBrowserPolicy(ctx context.Context, policyID string) error {
	_ = ctx
	state, err := loadBrowserPolicyState()
	if err != nil {
		return err
	}
	err = removeBrowserPolicyEntry(&state, strings.TrimSpace(policyID))
	if serr := saveBrowserPolicyState(state); err == nil {
		err = serr
	}
	return err
}

// CleanupOrphanedBrowserPolicies removes every recorded BROWSER_POLICY whose ID is not
// in active. It returns the IDs it cleaned up.
func CleanupOrphanedBrowserPolicies(ctx context.Context, active map[string]bool) []string {
	_ = ctx
	state, err := loadBrowserPolicyState()
	if err != nil {
		return nil
	}
	var cleaned []string
	for id := range state.Policies {
		if active[id] {
			continue
		}
		if removeBrowserPolicyEntry(&state, id) == nil {
			cleaned = append(cleaned, id)
		}
	}
	if len(cleaned) > 0 {
		_ = saveBrowserPolicyState(state)
	}
	sort.Strings(cleaned)
	return cleaned
}

func removeBrowserPolicyEntry(state *browserPolicyState, id string) error {
	entry := state.Policies[id]
	if entry == nil {
		return nil
	}
	removeBrowserPolicyChromium(entry)
	err := applyBrowserPolicyFirefox(state, entry, nil)
	if err == nil && len(entry.Firefox) == 0 {
		delete(state.Policies, id)
	}
	return err
}

func removeBrowserPolicyChromium(entry *browserPolicyEntry) {
	for _, p := range entry.ChromiumFiles {
		_ = os.Remove(p)
	}
	entry.ChromiumFiles, entry.ChromiumKeys = nil, nil
}

// applyBrowserPolicyFirefox makes every Firefox policies.json hold exactly the given slots
// for this policy: new slots are written (recording what they held before), and slots the
// policy no longer sets are restored. With nil slots it removes the policy from Firefox.
func applyBrowserPolicyFirefox(state *browserPolicyState, entry *browserPolicyEntry, slots map[string]json.RawMessage) error {
	if entry.Firefox == nil {
		entry.Firefox = map[string]map[string]browserPolicySlot{}
	}
	targets := map[string]bool{}
	if len(slots) > 0 {
		for _, p := range firefoxPolicyTargets() {
			targets[p] = true
		}
	}
	paths := map[string]bool{}
	for p := range targets {
		paths[p] = true
	}
	for p := range entry.Firefox {
		paths[p] = true
	}
	ordered := make([]string, 0, len(paths))
	for p := range paths {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)

	var firstErr error
	for _, path := range ordered {
		want := slots
		if !targets[path] {
			want = nil
		}
		if err := syncFirefoxFile(state, entry, path, want); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func syncFirefoxFile(state *browserPolicyState, entry *browserPolicyEntry, path string, want map[string]json.RawMessage) error {
	top, policies, prefs, exists, err := readFirefoxPolicies(path)
	if err != nil {
		return err
	}
	recorded := entry.Firefox[path]
	if recorded == nil {
		recorded = map[string]browserPolicySlot{}
	}
	if !exists && len(want) == 0 {
		delete(entry.Firefox, path)
		return nil
	}

	get := func(slot string) (json.RawMessage, bool) {
		if name, ok := strings.CutPrefix(slot, firefoxPrefSlotPrefix); ok {
			v, ok := prefs[name]
			return v, ok
		}
		v, ok := policies[slot]
		return v, ok
	}
	set := func(slot string, v json.RawMessage, present bool) {
		m, key := policies, slot
		if name, ok := strings.CutPrefix(slot, firefoxPrefSlotPrefix); ok {
			m, key = prefs, name
		}
		if present {
			m[key] = v
		} else {
			delete(m, key)
		}
	}

	// Restore slots this policy no longer sets.
	for slot, s := range recorded {
		if _, keep := want[slot]; keep {
			continue
		}
		if cur, ok := get(slot); ok && jsonEqual(cur, s.Written) {
			set(slot, s.Prior, s.HadPrior)
		}
		delete(recorded, slot)
	}
	// Write the slots it sets.
	for slot, v := range want {
		s, known := recorded[slot]
		if !known {
			s.Prior, s.HadPrior = get(slot)
		}
		s.Written = v
		set(slot, v, true)
		recorded[slot] = s
	}

	if !exists {
		state.FirefoxCreated[path] = true
	}
	empty := len(prefs) == 0 && len(top) <= 1
	for k := range policies {
		if k != firefoxPrefsKey {
			empty = false
		}
	}
	if empty && state.FirefoxCreated[path] {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		delete(state.FirefoxCreated, path)
	} else if err := writeFirefoxPolicies(path, top, policies, prefs); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if len(recorded) == 0 {
		delete(entry.Firefox, path)
	} else {
		entry.Firefox[path] = recorded
	}
	return nil
}

// readFirefoxSlots returns the current value of every slot in a policies.json.
func readFirefoxSlots(path string) (map[string]json.RawMessage, error) {
	_, policies, prefs, exists, err := readFirefoxPolicies(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("file is missing")
	}
	out := map[string]json.RawMessage{}
	for k, v := range policies {
		if k != firefoxPrefsKey {
			out[k] = v
		}
	}
	for k, v := range prefs {
		out[firefoxPrefSlotPrefix+k] = v
	}
	return out, nil
}

func rawMapsEqual(a, b map[string]json.RawMessage) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || !jsonEqual(v, w) {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func loadBrowserPolicyState() (browserPolicyState, error) {
	s := browserPolicyState{}
	data, err := os.ReadFile(browserPolicyStatePath())
	if err != nil && !os.IsNotExist(err) {
		return s, err
	}
	if err == nil {
		if err := json.Unmarshal(data, &s); err != nil {
			return s, fmt.Errorf("parse %s: %w", browserPolicyStatePath(), err)
		}
	}
	if s.Policies == nil {
		s.Policies = map[string]*browserPolicyEntry{}
	}
	if s.FirefoxCreated == nil {
		s.FirefoxCreated = map[string]bool{}
	}
	return s, nil
}

func saveBrowserPolicyState(s browserPolicyState) error {
	p := browserPolicyStatePath()
	if len(s.Policies) == 0 && len(s.FirefoxCreated) == 0 {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteBrowserFile(p, b, 0600)
}
