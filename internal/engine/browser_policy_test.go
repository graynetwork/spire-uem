package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func bpPolicy(id, payload string) types.AssignedPolicy {
	return types.AssignedPolicy{ID: id, PolicyType: types.PolicyTypeBrowserPolicy, Payload: json.RawMessage(payload)}
}

func mustCompliant(t *testing.T, item types.PolicyExecutionItem) {
	t.Helper()
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("status %s: %s", item.ComplianceStatus, item.ErrorMessage)
	}
}

func readFFPolicies(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	p, _ := top["policies"].(map[string]any)
	return p
}

func TestValidateBrowserPolicyPayload(t *testing.T) {
	ok := []string{
		`{"chromium":{"HomepageLocation":"https://intranet.example.com"}}`,
		`{"firefox":{"DisableTelemetry":true,"Preferences":{"browser.startup.homepage":{"Value":"x","Status":"locked"}}}}`,
	}
	for _, s := range ok {
		var p types.BrowserPolicyPayload
		if err := json.Unmarshal([]byte(s), &p); err != nil {
			t.Fatal(err)
		}
		if err := ValidateBrowserPolicyPayload(p); err != nil {
			t.Errorf("%s refused: %v", s, err)
		}
	}
	bad := map[string]string{
		"empty":                  `{}`,
		"path in chromium key":   `{"chromium":{"../x":1}}`,
		"lowercase key":          `{"chromium":{"homepage":1}}`,
		"null value":             `{"chromium":{"HomepageLocation":null}}`,
		"reserved chromium key":  `{"chromium":{"AutoSelectCertificateForUrls":[]}}`,
		"reserved firefox pref":  `{"firefox":{"Preferences":{"security.default_personal_cert":{"Value":"Ask Every Time"}}}}`,
		"preferences not object": `{"firefox":{"Preferences":[1]}}`,
		"empty preferences":      `{"firefox":{"Preferences":{}}}`,
		"bad pref name":          `{"firefox":{"Preferences":{"a/b":1}}}`,
	}
	for name, s := range bad {
		var p types.BrowserPolicyPayload
		if err := json.Unmarshal([]byte(s), &p); err != nil {
			t.Fatal(err)
		}
		if err := ValidateBrowserPolicyPayload(p); err == nil {
			t.Errorf("%s: accepted %s", name, s)
		}
	}
	big := map[string]json.RawMessage{}
	for i := 0; i < maxBrowserPolicyKeys+1; i++ {
		big["K"+strings.Repeat("a", i%50)+string(rune('A'+i%26))+string(rune('A'+i/26))] = json.RawMessage(`1`)
	}
	if err := ValidateBrowserPolicyPayload(types.BrowserPolicyPayload{Chromium: big}); err == nil {
		t.Error("too many keys accepted")
	}
}

func TestBrowserPolicy_ChromiumFilePerPolicy(t *testing.T) {
	root := withBrowserCertRoot(t)
	ctx := context.Background()
	mustCompliant(t, EnforceBrowserPolicy(ctx, bpPolicy("p1", `{"chromium":{"HomepageLocation":"https://a.example.com","MetricsReportingEnabled":false}}`)))

	for _, rel := range chromiumManagedDirs {
		path := filepath.Join(root, rel, "spire-policy-p1.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if got["HomepageLocation"] != "https://a.example.com" || got["MetricsReportingEnabled"] != false {
			t.Errorf("%s = %v", path, got)
		}
	}
	if err := RemoveBrowserPolicy(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	for _, rel := range chromiumManagedDirs {
		if _, err := os.Stat(filepath.Join(root, rel, "spire-policy-p1.json")); !os.IsNotExist(err) {
			t.Errorf("%s not removed", rel)
		}
	}
	if _, err := os.Stat(browserPolicyStatePath()); !os.IsNotExist(err) {
		t.Error("state file left behind")
	}
}

// Firefox keys are merged into an existing policies.json and restored on removal, keeping
// every key SpireUEM did not write.
func TestBrowserPolicy_FirefoxMergeAndRestore(t *testing.T) {
	root := withBrowserCertRoot(t)
	ctx := context.Background()
	path := filepath.Join(root, firefoxPolicyDefault)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	orig := `{"policies":{"DisableTelemetry":false,"BlockAboutConfig":true,"Preferences":{"other.pref":{"Value":1}}}}`
	if err := os.WriteFile(path, []byte(orig), 0644); err != nil {
		t.Fatal(err)
	}
	mustCompliant(t, EnforceBrowserPolicy(ctx, bpPolicy("p1",
		`{"firefox":{"DisableTelemetry":true,"Homepage":{"URL":"https://a.example.com"},"Preferences":{"browser.x":{"Value":"y"}}}}`)))

	p := readFFPolicies(t, path)
	if p["DisableTelemetry"] != true || p["BlockAboutConfig"] != true || p["Homepage"] == nil {
		t.Errorf("after apply: %v", p)
	}
	prefs := p["Preferences"].(map[string]any)
	if prefs["other.pref"] == nil || prefs["browser.x"] == nil {
		t.Errorf("prefs after apply: %v", prefs)
	}

	// Dropping a key from the policy restores it, and the rest stays.
	mustCompliant(t, EnforceBrowserPolicy(ctx, bpPolicy("p1", `{"firefox":{"Homepage":{"URL":"https://a.example.com"}}}`)))
	p = readFFPolicies(t, path)
	if p["DisableTelemetry"] != false {
		t.Errorf("DisableTelemetry not restored: %v", p)
	}
	if _, ok := p["Preferences"].(map[string]any)["browser.x"]; ok {
		t.Error("browser.x not removed")
	}

	if err := RemoveBrowserPolicy(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	p = readFFPolicies(t, path)
	var want map[string]any
	_ = json.Unmarshal([]byte(orig), &want)
	wb, _ := json.Marshal(want["policies"])
	gb, _ := json.Marshal(p)
	if string(wb) != string(gb) {
		t.Errorf("not restored:\n got %s\nwant %s", gb, wb)
	}
}

// A key someone else changed after SpireUEM wrote it is left alone on removal.
func TestBrowserPolicy_FirefoxLeavesForeignChange(t *testing.T) {
	root := withBrowserCertRoot(t)
	ctx := context.Background()
	mustCompliant(t, EnforceBrowserPolicy(ctx, bpPolicy("p1", `{"firefox":{"DisableTelemetry":true}}`)))
	path := filepath.Join(root, firefoxPolicyDefault)
	if err := os.WriteFile(path, []byte(`{"policies":{"DisableTelemetry":"changed"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := RemoveBrowserPolicy(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if p := readFFPolicies(t, path); p["DisableTelemetry"] != "changed" {
		t.Errorf("foreign value overwritten: %v", p)
	}
}

// A policies.json SpireUEM created is deleted once nothing is left in it, but not while
// BROWSER_CERTIFICATE still has its preference there.
func TestBrowserPolicy_FirefoxCreatedFileLifecycle(t *testing.T) {
	root := withBrowserCertRoot(t)
	ctx := context.Background()
	path := filepath.Join(root, firefoxPolicyDefault)

	mustCompliant(t, EnforceBrowserPolicy(ctx, bpPolicy("p1", `{"firefox":{"DisableTelemetry":true}}`)))
	if err := RemoveBrowserPolicy(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("created policies.json not removed")
	}

	mustCompliant(t, EnforceBrowserPolicy(ctx, bpPolicy("p1", `{"firefox":{"DisableTelemetry":true}}`)))
	cert := EnforceBrowserCertificatePolicy(ctx, bcPolicy(t, types.BrowserCertificatePayload{Browsers: []string{"firefox"}}))
	mustCompliant(t, cert)
	if err := RemoveBrowserPolicy(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	p := readFFPolicies(t, path)
	if _, ok := p["DisableTelemetry"]; ok {
		t.Error("DisableTelemetry left behind")
	}
	if p["Preferences"].(map[string]any)[firefoxPrefKey] == nil {
		t.Error("BROWSER_CERTIFICATE preference removed")
	}
	if err := RemoveBrowserCertificate(ctx); err != nil {
		t.Fatal(err)
	}
}

// Two BROWSER_POLICY policies may not set the same key.
func TestBrowserPolicy_ConflictRefused(t *testing.T) {
	root := withBrowserCertRoot(t)
	ctx := context.Background()
	mustCompliant(t, EnforceBrowserPolicy(ctx, bpPolicy("p1", `{"chromium":{"HomepageLocation":"https://a"},"firefox":{"DisableTelemetry":true}}`)))

	for _, payload := range []string{
		`{"chromium":{"HomepageLocation":"https://b"}}`,
		`{"firefox":{"DisableTelemetry":false}}`,
	} {
		item := EnforceBrowserPolicy(ctx, bpPolicy("p2", payload))
		if item.ComplianceStatus == types.ComplianceCompliant || !strings.Contains(item.ErrorMessage, "conflict") {
			t.Errorf("%s: %s %q", payload, item.ComplianceStatus, item.ErrorMessage)
		}
	}
	if p := readFFPolicies(t, filepath.Join(root, firefoxPolicyDefault)); p["DisableTelemetry"] != true {
		t.Errorf("p1's value overwritten: %v", p)
	}
	if _, err := os.Stat(filepath.Join(root, chromiumManagedDirs[0], "spire-policy-p2.json")); !os.IsNotExist(err) {
		t.Error("conflicting policy wrote a file")
	}
	// Different keys are fine.
	mustCompliant(t, EnforceBrowserPolicy(ctx, bpPolicy("p2", `{"chromium":{"BookmarkBarEnabled":true}}`)))
}

func TestBrowserPolicy_OrphanCleanup(t *testing.T) {
	root := withBrowserCertRoot(t)
	ctx := context.Background()
	mustCompliant(t, EnforceBrowserPolicy(ctx, bpPolicy("p1", `{"chromium":{"HomepageLocation":"https://a"}}`)))
	mustCompliant(t, EnforceBrowserPolicy(ctx, bpPolicy("p2", `{"firefox":{"DisableTelemetry":true}}`)))

	cleaned := CleanupOrphanedBrowserPolicies(ctx, map[string]bool{"p1": true})
	if len(cleaned) != 1 || cleaned[0] != "p2" {
		t.Fatalf("cleaned = %v", cleaned)
	}
	if _, err := os.Stat(filepath.Join(root, chromiumManagedDirs[0], "spire-policy-p1.json")); err != nil {
		t.Error("active policy removed")
	}
	if _, err := os.Stat(filepath.Join(root, firefoxPolicyDefault)); !os.IsNotExist(err) {
		t.Error("orphan's policies.json left behind")
	}
}

func TestBrowserPolicy_InvalidPolicyIDRefused(t *testing.T) {
	root := withBrowserCertRoot(t)
	// Without the id check this resolves to <root>/escape.json from the first managed dir.
	item := EnforceBrowserPolicy(context.Background(), bpPolicy("a/../../../../../../escape", `{"chromium":{"HomepageLocation":"https://a"}}`))
	if item.ComplianceStatus == types.ComplianceCompliant {
		t.Error("path-like policy id accepted")
	}
	if _, err := os.Stat(filepath.Join(root, "escape.json")); !os.IsNotExist(err) {
		t.Error("policy file written outside the managed directory")
	}
}

// A policies.json that existed before is kept even when SpireUEM's removal empties it.
func TestBrowserPolicy_FirefoxKeepsPreexistingEmptyFile(t *testing.T) {
	root := withBrowserCertRoot(t)
	ctx := context.Background()
	path := filepath.Join(root, firefoxPolicyDefault)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"policies":{}}`), 0644); err != nil {
		t.Fatal(err)
	}
	mustCompliant(t, EnforceBrowserPolicy(ctx, bpPolicy("p1", `{"firefox":{"DisableTelemetry":true}}`)))
	if err := RemoveBrowserPolicy(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("pre-existing policies.json deleted: %v", err)
	}
}

func TestBrowserTelemetryTemplateIsValid(t *testing.T) {
	tpl, ok := types.GetPolicyTemplateByID("browser-telemetry-baseline")
	if !ok {
		t.Fatal("template missing")
	}
	var p types.BrowserPolicyPayload
	if err := json.Unmarshal(tpl.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBrowserPolicyPayload(p); err != nil {
		t.Fatal(err)
	}
}
