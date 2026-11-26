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

// BROWSER_CERTIFICATE engine. The policy does two things on the endpoint:
//
//   - Chromium-family browsers (Chrome, Chromium, Brave, Edge): writes a managed policy file of
//     SpireUEM's own, with AutoSelectCertificateForUrls limited to the device CA as issuer.
//   - Firefox: Firefox reads a single policies.json, so SpireUEM merges ONE preference
//     (security.default_personal_cert) into it and records what it replaced. Removal puts the
//     file back the way it was, keeping every key SpireUEM did not write.
//
// The certificates themselves are issued to each desktop user by spire-hub through the agent IPC.

const (
	// DeviceCAIssuerCN is the common name of the device CA that signs every browser certificate.
	DeviceCAIssuerCN = "SpireUEM Device CA"

	browserCertChromiumFile = "spire-browser-cert.json"
	firefoxPrefKey          = "security.default_personal_cert"
	firefoxPrefValue        = "Select Automatically"
	maxAutoSelectURLs       = 64
)

var (
	// browserCertRoot is the filesystem root. "" means the real root. Tests set a temp dir.
	browserCertRoot = ""

	// chromiumManagedDirs are the managed-policy directories of the Chromium-family browsers,
	// relative to the root.
	chromiumManagedDirs = []string{
		"etc/opt/chrome/policies/managed",
		"etc/chromium/policies/managed",
		"etc/brave/policies/managed",
		"etc/opt/edge/policies/managed",
	}
	// firefoxPolicyDefault is always written. The others are written only when their
	// distribution directory already exists.
	firefoxPolicyDefault = "etc/firefox/policies/policies.json"
	firefoxPolicyOthers  = []string{
		"usr/lib/firefox/distribution/policies.json",
		"usr/lib/firefox-esr/distribution/policies.json",
		"usr/lib64/firefox/distribution/policies.json",
		"opt/firefox/distribution/policies.json",
	}

	// autoSelectURLRe accepts "https://host[:port]", "host", and "[*.]host" forms of Chrome's
	// content-setting patterns. A bare "*", plain http and paths are refused.
	autoSelectURLRe = regexp.MustCompile(`^(https://)?(\[\*\.\])?[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:[0-9]{1,5})?$`)
)

// browserCertState records what SpireUEM wrote, so removal undoes exactly that.
type browserCertState struct {
	ChromiumFiles []string             `json:"chromium_files,omitempty"`
	Firefox       []firefoxPolicyState `json:"firefox,omitempty"`
}

type firefoxPolicyState struct {
	Path     string          `json:"path"`
	Created  bool            `json:"created"`         // SpireUEM created the file
	HadPrior bool            `json:"had_prior"`       // the preference existed before
	Prior    json.RawMessage `json:"prior,omitempty"` // its previous value
	Written  json.RawMessage `json:"written"`         // the value SpireUEM wrote
}

func browserCertPath(rel string) string {
	if browserCertRoot == "" {
		return "/" + rel
	}
	return filepath.Join(browserCertRoot, rel)
}

func browserCertStatePath() string {
	return browserCertPath("var/lib/spire/browser-cert/state.json")
}

// ValidateBrowserCertificatePayload validates a BROWSER_CERTIFICATE payload before it is stored.
func ValidateBrowserCertificatePayload(p types.BrowserCertificatePayload) error {
	_, err := normalizeBrowserCertPayload(p)
	return err
}

type browserCertPlan struct {
	chromium bool
	firefox  bool
	urls     []string
}

func normalizeBrowserCertPayload(p types.BrowserCertificatePayload) (browserCertPlan, error) {
	var plan browserCertPlan
	if len(p.Browsers) == 0 {
		plan.chromium, plan.firefox = true, true
	}
	for _, b := range p.Browsers {
		switch strings.ToLower(strings.TrimSpace(b)) {
		case types.BrowserFamilyChromium:
			plan.chromium = true
		case types.BrowserFamilyFirefox:
			plan.firefox = true
		default:
			return plan, fmt.Errorf("unknown browser %q (chromium|firefox)", b)
		}
	}
	if len(p.AutoSelectURLs) > maxAutoSelectURLs {
		return plan, fmt.Errorf("at most %d auto_select_urls are allowed", maxAutoSelectURLs)
	}
	seen := map[string]bool{}
	for i, u := range p.AutoSelectURLs {
		u = strings.TrimSpace(u)
		if !autoSelectURLRe.MatchString(u) {
			return plan, fmt.Errorf("auto_select_urls[%d]: %q is not a valid pattern (use https://host, host or [*.]host)", i, u)
		}
		if !seen[u] {
			seen[u] = true
			plan.urls = append(plan.urls, u)
		}
	}
	if plan.chromium && len(plan.urls) == 0 {
		return plan, fmt.Errorf("at least one auto_select_urls pattern is required for chromium browsers")
	}
	return plan, nil
}

// chromiumPolicyJSON renders the managed policy file content.
func chromiumPolicyJSON(urls []string) ([]byte, error) {
	entries := make([]string, 0, len(urls))
	for _, u := range urls {
		entry := map[string]any{
			"pattern": u,
			"filter":  map[string]any{"ISSUER": map[string]string{"CN": DeviceCAIssuerCN}},
		}
		b, err := json.Marshal(entry)
		if err != nil {
			return nil, err
		}
		entries = append(entries, string(b))
	}
	return json.MarshalIndent(map[string]any{"AutoSelectCertificateForUrls": entries}, "", "  ")
}

// EnforceBrowserCertificatePolicy applies the policy: it writes the Chromium-family managed
// policy files and merges the Firefox preference, then reads both back to confirm.
func EnforceBrowserCertificatePolicy(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	var payload types.BrowserCertificatePayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return failItem(policy.ID, fmt.Sprintf("invalid BROWSER_CERTIFICATE payload: %v", err), nil)
	}
	plan, err := normalizeBrowserCertPayload(payload)
	if err != nil {
		return failItem(policy.ID, err.Error(), nil)
	}
	details := map[string]any{
		"policy_id": policy.ID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	state, err := loadBrowserCertState()
	if err != nil {
		return failItem(policy.ID, fmt.Sprintf("read state: %v", err), details)
	}

	// A browser family dropped from the policy is cleaned up before the rest is applied.
	if !plan.chromium {
		removeChromiumFiles(&state)
	}
	if !plan.firefox {
		if err := removeFirefoxPrefs(&state); err != nil {
			return failItem(policy.ID, err.Error(), details)
		}
	}

	if plan.chromium {
		content, err := chromiumPolicyJSON(plan.urls)
		if err != nil {
			return failItem(policy.ID, err.Error(), details)
		}
		content = append(content, '\n')
		var written []string
		for _, rel := range chromiumManagedDirs {
			dir := browserCertPath(rel)
			path := filepath.Join(dir, browserCertChromiumFile)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return failItem(policy.ID, fmt.Sprintf("mkdir %s: %v", dir, err), details)
			}
			if err := atomicWriteBrowserFile(path, content, 0644); err != nil {
				return failItem(policy.ID, fmt.Sprintf("write %s: %v", path, err), details)
			}
			written = append(written, path)
		}
		state.ChromiumFiles = written
		details["chromium_files"] = written
	}

	if plan.firefox {
		if err := applyFirefoxPref(&state); err != nil {
			_ = saveBrowserCertState(state)
			return failItem(policy.ID, err.Error(), details)
		}
		paths := make([]string, 0, len(state.Firefox))
		for _, f := range state.Firefox {
			paths = append(paths, f.Path)
		}
		details["firefox_policy_files"] = paths
	}
	if err := saveBrowserCertState(state); err != nil {
		return failItem(policy.ID, fmt.Sprintf("write state: %v", err), details)
	}

	// Read back.
	if plan.chromium {
		want, _ := chromiumPolicyJSON(plan.urls)
		for _, p := range state.ChromiumFiles {
			got, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
				return failItem(policy.ID, fmt.Sprintf("verification failed for %s", p), details)
			}
		}
	}
	if plan.firefox {
		for _, f := range state.Firefox {
			if !firefoxPrefIs(f.Path, firefoxPrefValueJSON()) {
				return failItem(policy.ID, fmt.Sprintf("verification failed for %s", f.Path), details)
			}
		}
	}
	return types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  mustJSON(details),
	}
}

// RemoveBrowserCertificate removes exactly what EnforceBrowserCertificatePolicy wrote.
func RemoveBrowserCertificate(ctx context.Context) error {
	state, err := loadBrowserCertState()
	if err != nil {
		return err
	}
	removeChromiumFiles(&state)
	ferr := removeFirefoxPrefs(&state)
	if ferr != nil {
		_ = saveBrowserCertState(state)
		return ferr
	}
	_ = os.Remove(browserCertStatePath())
	return nil
}

func removeChromiumFiles(state *browserCertState) {
	for _, p := range state.ChromiumFiles {
		_ = os.Remove(p)
	}
	state.ChromiumFiles = nil
}

func firefoxPrefValueJSON() json.RawMessage {
	b, _ := json.Marshal(map[string]string{"Value": firefoxPrefValue, "Status": "default"})
	return b
}

// firefoxPolicyTargets returns the real paths of the policies.json files to manage, with
// symlinks resolved and duplicates removed.
func firefoxPolicyTargets() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if real, err := filepath.EvalSymlinks(p); err == nil {
			p = real
		} else if real, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
			p = filepath.Join(real, filepath.Base(p))
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	add(browserCertPath(firefoxPolicyDefault))
	for _, rel := range firefoxPolicyOthers {
		p := browserCertPath(rel)
		if st, err := os.Stat(filepath.Dir(p)); err == nil && st.IsDir() {
			add(p)
		}
	}
	sort.Strings(out)
	return out
}

// readFirefoxPolicies parses a policies.json into raw maps, preserving every key's raw value.
// A missing file gives empty maps and exists=false. A file that does not parse is an error:
// SpireUEM does not overwrite a file it cannot understand.
func readFirefoxPolicies(path string) (top, policies, prefs map[string]json.RawMessage, exists bool, err error) {
	top, policies, prefs = map[string]json.RawMessage{}, map[string]json.RawMessage{}, map[string]json.RawMessage{}
	data, rerr := os.ReadFile(path)
	if os.IsNotExist(rerr) {
		return top, policies, prefs, false, nil
	}
	if rerr != nil {
		return nil, nil, nil, true, rerr
	}
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &top); err != nil {
			return nil, nil, nil, true, fmt.Errorf("%s is not valid JSON, left untouched: %w", path, err)
		}
		if top == nil {
			top = map[string]json.RawMessage{}
		}
	}
	if raw, ok := top["policies"]; ok {
		if err := json.Unmarshal(raw, &policies); err != nil || policies == nil {
			return nil, nil, nil, true, fmt.Errorf("%s: \"policies\" is not an object, left untouched", path)
		}
	}
	if raw, ok := policies["Preferences"]; ok {
		if err := json.Unmarshal(raw, &prefs); err != nil || prefs == nil {
			return nil, nil, nil, true, fmt.Errorf("%s: \"Preferences\" is not an object, left untouched", path)
		}
	}
	return top, policies, prefs, true, nil
}

func writeFirefoxPolicies(path string, top, policies, prefs map[string]json.RawMessage) error {
	if len(prefs) > 0 {
		b, _ := json.Marshal(prefs)
		policies["Preferences"] = b
	} else {
		delete(policies, "Preferences")
	}
	b, _ := json.Marshal(policies)
	top["policies"] = b
	out, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return atomicWriteBrowserFile(path, append(out, '\n'), 0644)
}

func applyFirefoxPref(state *browserCertState) error {
	want := firefoxPrefValueJSON()
	byPath := map[string]firefoxPolicyState{}
	for _, f := range state.Firefox {
		byPath[f.Path] = f
	}
	var next []firefoxPolicyState
	targets := firefoxPolicyTargets()
	targetSet := map[string]bool{}
	for _, path := range targets {
		targetSet[path] = true
		top, policies, prefs, exists, err := readFirefoxPolicies(path)
		if err != nil {
			return err
		}
		st, known := byPath[path]
		if !known {
			st = firefoxPolicyState{Path: path, Created: !exists}
			if prior, ok := prefs[firefoxPrefKey]; ok {
				st.HadPrior, st.Prior = true, prior
			}
		}
		st.Written = want
		prefs[firefoxPrefKey] = want
		if err := writeFirefoxPolicies(path, top, policies, prefs); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		next = append(next, st)
	}
	// A file SpireUEM managed earlier that is no longer a target is cleaned up.
	var stale browserCertState
	for _, f := range state.Firefox {
		if !targetSet[f.Path] {
			stale.Firefox = append(stale.Firefox, f)
		}
	}
	if err := removeFirefoxPrefs(&stale); err != nil {
		return err
	}
	state.Firefox = next
	return nil
}

// removeFirefoxPrefs undoes applyFirefoxPref for each recorded file.
func removeFirefoxPrefs(state *browserCertState) error {
	var firstErr error
	var remaining []firefoxPolicyState
	for _, f := range state.Firefox {
		if err := removeFirefoxPref(f); err != nil {
			remaining = append(remaining, f)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	state.Firefox = remaining
	return firstErr
}

func removeFirefoxPref(f firefoxPolicyState) error {
	top, policies, prefs, exists, err := readFirefoxPolicies(f.Path)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	cur, ok := prefs[firefoxPrefKey]
	// Only touch the key if it still holds what SpireUEM wrote; someone else changed it otherwise.
	if ok && jsonEqual(cur, f.Written) {
		if f.HadPrior {
			prefs[firefoxPrefKey] = f.Prior
		} else {
			delete(prefs, firefoxPrefKey)
		}
	}
	// A file SpireUEM created and that now holds nothing else is removed.
	if f.Created && len(prefs) == 0 && len(top) <= 1 {
		onlyPrefs := true
		for k := range policies {
			if k != "Preferences" {
				onlyPrefs = false
			}
		}
		if onlyPrefs {
			return os.Remove(f.Path)
		}
	}
	return writeFirefoxPolicies(f.Path, top, policies, prefs)
}

func firefoxPrefIs(path string, want json.RawMessage) bool {
	_, _, prefs, exists, err := readFirefoxPolicies(path)
	if err != nil || !exists {
		return false
	}
	cur, ok := prefs[firefoxPrefKey]
	return ok && jsonEqual(cur, want)
}

func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}

func loadBrowserCertState() (browserCertState, error) {
	var s browserCertState
	data, err := os.ReadFile(browserCertStatePath())
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("parse %s: %w", browserCertStatePath(), err)
	}
	return s, nil
}

func saveBrowserCertState(s browserCertState) error {
	p := browserCertStatePath()
	if len(s.ChromiumFiles) == 0 && len(s.Firefox) == 0 {
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

// atomicWriteBrowserFile writes through a temp file in the same directory and renames it in.
func atomicWriteBrowserFile(path string, data []byte, mode os.FileMode) error {
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".spire-bc-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
