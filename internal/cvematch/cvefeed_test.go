package cvematch

import (
	"os"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func loadFixtureEntries(t *testing.T) []types.CVEEntry {
	t.Helper()
	f, err := os.Open("testdata/debian_cve_fixture.json")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	var entries []types.CVEEntry
	n, err := StreamDebianFeed(f, func(e types.CVEEntry) error {
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamDebianFeed: %v", err)
	}
	if n != len(entries) {
		t.Fatalf("count mismatch: returned %d, collected %d", n, len(entries))
	}
	return entries
}

func TestStreamDebianFeed(t *testing.T) {
	entries := loadFixtureEntries(t)

	// openssl: 2 releases on CVE-2024-0001 + 1 release on CVE-2024-0002 = 3
	// bash:    1
	// TEMP-... : CVE-NOT-REAL is skipped (not a CVE- key)
	if len(entries) != 4 {
		t.Fatalf("expected 4 emitted entries, got %d: %+v", len(entries), entries)
	}

	var found0001Bookworm bool
	for _, e := range entries {
		if strings.HasPrefix(e.CVEID, "TEMP-") {
			t.Errorf("non-CVE key leaked into entries: %+v", e)
		}
		if e.CVEID == "CVE-2024-0001" && e.Release == "bookworm" {
			found0001Bookworm = true
			if e.Status != types.CVEStatusResolved {
				t.Errorf("CVE-2024-0001 bookworm status = %q, want resolved", e.Status)
			}
			if e.FixedVersion != "3.0.11-1~deb12u2" {
				t.Errorf("CVE-2024-0001 fixed_version = %q", e.FixedVersion)
			}
			if e.Urgency != "high" {
				t.Errorf("CVE-2024-0001 urgency = %q, want high", e.Urgency)
			}
			if !strings.Contains(e.Description, "buffer overflow") {
				t.Errorf("CVE-2024-0001 description missing: %q", e.Description)
			}
		}
	}
	if !found0001Bookworm {
		t.Error("CVE-2024-0001 bookworm entry not emitted")
	}
}

// buildLookup turns a flat entry list into the per-source-package, index-based lookup the
// matcher expects (it never scans the full list).
func buildLookup(entries []types.CVEEntry) func(string) []types.CVEEntry {
	idx := make(map[string][]types.CVEEntry)
	for _, e := range entries {
		idx[e.SourcePackage] = append(idx[e.SourcePackage], e)
	}
	return func(src string) []types.CVEEntry { return idx[src] }
}

func TestMatchDeviceCVEs(t *testing.T) {
	lookup := buildLookup(loadFixtureEntries(t))

	t.Run("vulnerable: installed older than fixed", func(t *testing.T) {
		installed := []types.ReportedPackage{
			{Name: "libssl3", Source: "openssl", SourceVersion: "3.0.11-1~deb12u1"}, // < fixed u2
			{Name: "bash", Source: "bash", SourceVersion: "5.2.15-2+b7"},            // open => no-fix
		}
		matches := MatchDeviceCVEs(installed, "bookworm", lookup)
		got := map[string]types.DeviceCVEMatch{}
		for _, m := range matches {
			got[m.CVEID] = m
		}
		if _, ok := got["CVE-2024-0001"]; !ok {
			t.Fatalf("expected CVE-2024-0001 match, got %+v", matches)
		}
		if got["CVE-2024-0001"].NoFixAvailable {
			t.Error("CVE-2024-0001 should have a fix available")
		}
		if m, ok := got["CVE-2024-0003"]; !ok || !m.NoFixAvailable {
			t.Errorf("expected CVE-2024-0003 as no-fix-available, got %+v", got["CVE-2024-0003"])
		}
		// CVE-2024-0002 is undetermined -> never a match.
		if _, ok := got["CVE-2024-0002"]; ok {
			t.Error("undetermined CVE-2024-0002 must not match")
		}
	})

	t.Run("not vulnerable: installed at or above fixed clears it", func(t *testing.T) {
		installed := []types.ReportedPackage{
			{Name: "libssl3", Source: "openssl", SourceVersion: "3.0.11-1~deb12u2"}, // == fixed
		}
		matches := MatchDeviceCVEs(installed, "bookworm", lookup)
		for _, m := range matches {
			if m.CVEID == "CVE-2024-0001" {
				t.Errorf("CVE-2024-0001 should be cleared at fixed version, got %+v", m)
			}
		}
	})

	t.Run("release scoping: bullseye sees open, bookworm resolved", func(t *testing.T) {
		installed := []types.ReportedPackage{
			{Source: "openssl", SourceVersion: "3.0.11-1~deb12u2"}, // >= bookworm fix
		}
		// On bullseye the same CVE is "open" => vulnerable regardless of version.
		matches := MatchDeviceCVEs(installed, "bullseye", lookup)
		var hit bool
		for _, m := range matches {
			if m.CVEID == "CVE-2024-0001" {
				hit = true
				if !m.NoFixAvailable {
					t.Error("bullseye open CVE-2024-0001 should be no-fix-available")
				}
			}
		}
		if !hit {
			t.Errorf("expected bullseye open match for CVE-2024-0001, got %+v", matches)
		}
	})

	t.Run("empty release => no matching", func(t *testing.T) {
		installed := []types.ReportedPackage{{Source: "openssl", SourceVersion: "1.0.0"}}
		if m := MatchDeviceCVEs(installed, "", lookup); len(m) != 0 {
			t.Errorf("expected no matches for empty release, got %+v", m)
		}
	})
}
