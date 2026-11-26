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

func withBrowserCertRoot(t *testing.T) string {
	t.Helper()
	old := browserCertRoot
	browserCertRoot = t.TempDir()
	t.Cleanup(func() { browserCertRoot = old })
	return browserCertRoot
}

func bcPolicy(t *testing.T, p types.BrowserCertificatePayload) types.AssignedPolicy {
	t.Helper()
	b, _ := json.Marshal(p)
	return types.AssignedPolicy{ID: "pol-bc", PolicyType: types.PolicyTypeBrowserCertificate, Payload: b}
}

func TestValidateBrowserCertificatePayload(t *testing.T) {
	good := []types.BrowserCertificatePayload{
		{AutoSelectURLs: []string{"https://apps.example.com"}},
		{AutoSelectURLs: []string{"[*.]example.com", "https://a.example.com:8443"}, Browsers: []string{"chromium", "firefox"}},
		{Browsers: []string{"firefox"}},
	}
	for i, p := range good {
		if err := ValidateBrowserCertificatePayload(p); err != nil {
			t.Errorf("good[%d]: %v", i, err)
		}
	}
	bad := map[string]types.BrowserCertificatePayload{
		"no urls for chromium": {},
		"bare star":            {AutoSelectURLs: []string{"*"}},
		"plain http":           {AutoSelectURLs: []string{"http://x.example.com"}},
		"path":                 {AutoSelectURLs: []string{"https://x.example.com/a"}},
		"space":                {AutoSelectURLs: []string{"https://x .example.com"}},
		"quote":                {AutoSelectURLs: []string{`https://x"y`}},
		"star host":            {AutoSelectURLs: []string{"https://*"}},
		"unknown browser":      {AutoSelectURLs: []string{"https://x.example.com"}, Browsers: []string{"lynx"}},
		"too many": {AutoSelectURLs: func() []string {
			var u []string
			for i := 0; i < 65; i++ {
				u = append(u, "h"+strings.Repeat("a", i)+".example.com")
			}
			return u
		}()},
	}
	for name, p := range bad {
		if err := ValidateBrowserCertificatePayload(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestBrowserCert_ChromiumFilesWrittenAndRemoved(t *testing.T) {
	root := withBrowserCertRoot(t)
	item := EnforceBrowserCertificatePolicy(context.Background(), bcPolicy(t, types.BrowserCertificatePayload{
		AutoSelectURLs: []string{"https://apps.example.com"},
		Browsers:       []string{"chromium"},
	}))
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("expected compliant, got %s: %s", item.ComplianceStatus, item.ErrorMessage)
	}
	for _, rel := range chromiumManagedDirs {
		path := filepath.Join(root, rel, browserCertChromiumFile)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s not written: %v", rel, err)
		}
		var doc map[string][]string
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		entries := doc["AutoSelectCertificateForUrls"]
		if len(entries) != 1 {
			t.Fatalf("want 1 entry, got %v", entries)
		}
		var e struct {
			Pattern string `json:"pattern"`
			Filter  struct {
				Issuer struct{ CN string } `json:"ISSUER"`
			} `json:"filter"`
		}
		if err := json.Unmarshal([]byte(entries[0]), &e); err != nil {
			t.Fatal(err)
		}
		if e.Pattern != "https://apps.example.com" || e.Filter.Issuer.CN != "SpireUEM Device CA" {
			t.Errorf("entry = %+v", e)
		}
	}
	// Chromium-only: no Firefox file.
	if _, err := os.Stat(filepath.Join(root, firefoxPolicyDefault)); !os.IsNotExist(err) {
		t.Errorf("firefox policies.json must not exist for a chromium-only policy")
	}

	if err := RemoveBrowserCertificate(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, rel := range chromiumManagedDirs {
		if _, err := os.Stat(filepath.Join(root, rel, browserCertChromiumFile)); !os.IsNotExist(err) {
			t.Errorf("%s still present after removal", rel)
		}
	}
	if _, err := os.Stat(browserCertStatePath()); !os.IsNotExist(err) {
		t.Errorf("state file still present after removal")
	}
}

// A managed file that SpireUEM did not write must survive apply and remove.
func TestBrowserCert_OtherChromiumPolicyFilesUntouched(t *testing.T) {
	root := withBrowserCertRoot(t)
	dir := filepath.Join(root, chromiumManagedDirs[0])
	_ = os.MkdirAll(dir, 0755)
	other := filepath.Join(dir, "corp.json")
	_ = os.WriteFile(other, []byte(`{"HomepageLocation":"https://corp"}`), 0644)
	pol := bcPolicy(t, types.BrowserCertificatePayload{AutoSelectURLs: []string{"https://a.example.com"}, Browsers: []string{"chromium"}})
	if it := EnforceBrowserCertificatePolicy(context.Background(), pol); it.ComplianceStatus != types.ComplianceCompliant {
		t.Fatal(it.ErrorMessage)
	}
	if err := RemoveBrowserCertificate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(other); err != nil || string(b) != `{"HomepageLocation":"https://corp"}` {
		t.Errorf("foreign file changed: %v %q", err, b)
	}
}

const existingFirefoxPolicies = `{
  "policies": {
    "DisableTelemetry": true,
    "Homepage": {"URL": "https://intranet", "Locked": true},
    "Preferences": {
      "browser.startup.page": {"Value": 3, "Status": "default"},
      "security.default_personal_cert": {"Value": "Ask Every Time", "Status": "user"}
    }
  },
  "extra_top_level": [1, 2, 3]
}`

func readJSONFile(t *testing.T, p string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return m
}

func TestBrowserCert_FirefoxMergePreservesAndRestores(t *testing.T) {
	root := withBrowserCertRoot(t)
	path := filepath.Join(root, firefoxPolicyDefault)
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	if err := os.WriteFile(path, []byte(existingFirefoxPolicies), 0644); err != nil {
		t.Fatal(err)
	}
	var before map[string]any
	_ = json.Unmarshal([]byte(existingFirefoxPolicies), &before)

	pol := bcPolicy(t, types.BrowserCertificatePayload{Browsers: []string{"firefox"}})
	if it := EnforceBrowserCertificatePolicy(context.Background(), pol); it.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("%s: %s", it.ComplianceStatus, it.ErrorMessage)
	}
	after := readJSONFile(t, path)
	pols := after["policies"].(map[string]any)
	if pols["DisableTelemetry"] != true {
		t.Errorf("DisableTelemetry lost: %v", pols)
	}
	if hp := pols["Homepage"].(map[string]any); hp["URL"] != "https://intranet" {
		t.Errorf("Homepage changed: %v", hp)
	}
	if _, ok := after["extra_top_level"]; !ok {
		t.Errorf("top-level key lost")
	}
	prefs := pols["Preferences"].(map[string]any)
	if prefs["browser.startup.page"].(map[string]any)["Value"].(float64) != 3 {
		t.Errorf("foreign preference changed: %v", prefs)
	}
	if prefs["security.default_personal_cert"].(map[string]any)["Value"] != "Select Automatically" {
		t.Errorf("preference not set: %v", prefs)
	}

	// Apply twice: still compliant and the recorded prior value is not overwritten.
	if it := EnforceBrowserCertificatePolicy(context.Background(), pol); it.ComplianceStatus != types.ComplianceCompliant {
		t.Fatal(it.ErrorMessage)
	}

	if err := RemoveBrowserCertificate(context.Background()); err != nil {
		t.Fatal(err)
	}
	restored := readJSONFile(t, path)
	rb, _ := json.Marshal(restored)
	bb, _ := json.Marshal(before)
	if string(rb) != string(bb) {
		t.Errorf("file not restored.\n got %s\nwant %s", rb, bb)
	}
}

func TestBrowserCert_FirefoxCreatedFileRemoved(t *testing.T) {
	root := withBrowserCertRoot(t)
	path := filepath.Join(root, firefoxPolicyDefault)
	pol := bcPolicy(t, types.BrowserCertificatePayload{Browsers: []string{"firefox"}})
	if it := EnforceBrowserCertificatePolicy(context.Background(), pol); it.ComplianceStatus != types.ComplianceCompliant {
		t.Fatal(it.ErrorMessage)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("policies.json not created: %v", err)
	}
	if err := RemoveBrowserCertificate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("created policies.json should be removed, err=%v", err)
	}
}

// If an admin changed the preference after SpireUEM set it, removal leaves their value.
func TestBrowserCert_FirefoxChangedValueNotRemoved(t *testing.T) {
	root := withBrowserCertRoot(t)
	path := filepath.Join(root, firefoxPolicyDefault)
	pol := bcPolicy(t, types.BrowserCertificatePayload{Browsers: []string{"firefox"}})
	if it := EnforceBrowserCertificatePolicy(context.Background(), pol); it.ComplianceStatus != types.ComplianceCompliant {
		t.Fatal(it.ErrorMessage)
	}
	_ = os.WriteFile(path, []byte(`{"policies":{"Preferences":{"security.default_personal_cert":{"Value":"Ask Every Time","Status":"locked"}}}}`), 0644)
	if err := RemoveBrowserCertificate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "Ask Every Time") {
		t.Errorf("a value SpireUEM did not write must stay: %s", b)
	}
}

func TestBrowserCert_FirefoxBrokenFileNotClobbered(t *testing.T) {
	root := withBrowserCertRoot(t)
	path := filepath.Join(root, firefoxPolicyDefault)
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	_ = os.WriteFile(path, []byte(`{ not json`), 0644)
	it := EnforceBrowserCertificatePolicy(context.Background(), bcPolicy(t, types.BrowserCertificatePayload{Browsers: []string{"firefox"}}))
	if it.ComplianceStatus != types.ComplianceFailed {
		t.Fatalf("expected failure, got %s", it.ComplianceStatus)
	}
	if b, _ := os.ReadFile(path); string(b) != `{ not json` {
		t.Errorf("unparsable file was modified: %q", b)
	}
}

func TestBrowserCert_FirefoxSymlinkedPolicyFileHandledOnce(t *testing.T) {
	root := withBrowserCertRoot(t)
	real := filepath.Join(root, firefoxPolicyDefault)
	_ = os.MkdirAll(filepath.Dir(real), 0755)
	_ = os.WriteFile(real, []byte(`{"policies":{"DisableTelemetry":true}}`), 0644)
	link := filepath.Join(root, "usr/lib/firefox-esr/distribution/policies.json")
	_ = os.MkdirAll(filepath.Dir(link), 0755)
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	pol := bcPolicy(t, types.BrowserCertificatePayload{Browsers: []string{"firefox"}})
	if it := EnforceBrowserCertificatePolicy(context.Background(), pol); it.ComplianceStatus != types.ComplianceCompliant {
		t.Fatal(it.ErrorMessage)
	}
	if err := RemoveBrowserCertificate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(real); strings.Contains(string(b), "default_personal_cert") || !strings.Contains(string(b), "DisableTelemetry") {
		t.Errorf("symlinked file not restored: %s", b)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink was replaced: %v", err)
	}
}

// Dropping a browser family from the policy cleans that family up.
func TestBrowserCert_DroppedFamilyCleanedUp(t *testing.T) {
	root := withBrowserCertRoot(t)
	both := bcPolicy(t, types.BrowserCertificatePayload{AutoSelectURLs: []string{"https://a.example.com"}})
	if it := EnforceBrowserCertificatePolicy(context.Background(), both); it.ComplianceStatus != types.ComplianceCompliant {
		t.Fatal(it.ErrorMessage)
	}
	ffOnly := bcPolicy(t, types.BrowserCertificatePayload{Browsers: []string{"firefox"}})
	if it := EnforceBrowserCertificatePolicy(context.Background(), ffOnly); it.ComplianceStatus != types.ComplianceCompliant {
		t.Fatal(it.ErrorMessage)
	}
	if _, err := os.Stat(filepath.Join(root, chromiumManagedDirs[0], browserCertChromiumFile)); !os.IsNotExist(err) {
		t.Errorf("chromium file should be gone")
	}
	if _, err := os.Stat(filepath.Join(root, firefoxPolicyDefault)); err != nil {
		t.Errorf("firefox file should remain: %v", err)
	}
}

func TestBrowserCert_InvalidPayloadFailsWithoutWriting(t *testing.T) {
	root := withBrowserCertRoot(t)
	it := EnforceBrowserCertificatePolicy(context.Background(), bcPolicy(t, types.BrowserCertificatePayload{AutoSelectURLs: []string{"*"}}))
	if it.ComplianceStatus != types.ComplianceFailed {
		t.Fatalf("expected failed, got %s", it.ComplianceStatus)
	}
	if _, err := os.Stat(filepath.Join(root, "etc")); !os.IsNotExist(err) {
		t.Errorf("nothing may be written for an invalid payload")
	}
}
