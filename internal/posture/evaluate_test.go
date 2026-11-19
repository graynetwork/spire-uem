package posture

import (
	"strings"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

var t0 = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func ptrT(t time.Time) *time.Time { return &t }
func ptrB(b bool) *bool           { return &b }

// healthy returns facts that pass every check.
func healthy() Facts {
	return Facts{
		DeviceID:       "d1",
		Approved:       true,
		LastCheckinAt:  ptrT(t0.Add(-time.Hour)),
		Trust:          types.TrustEvaluation{Trusted: true, Reason: "attested"},
		DiskEncrypted:  ptrB(true),
		Policies:       []PolicyFact{{Name: "p", Status: types.ComplianceCompliant}},
		Patch:          &types.DevicePatchStatus{SecurityUpdatesCount: 0},
		GroupRuleMatch: true,
	}
}

func allOn() types.AccessRuleSet {
	rs := types.DefaultAccessRuleSet()
	rs.Version = 7
	rs.AttestationTrusted.Enabled = true
	rs.DiskEncrypted.Enabled = true
	rs.PoliciesCompliant.Enabled = true
	rs.PatchesCurrent.Enabled = true
	rs.NoCriticalCVEs.Enabled = true
	rs.NoCriticalCVEs.MinUrgency = "high"
	rs.GroupRule.Enabled = true
	return rs
}

func failedIDs(p types.DevicePosture) string {
	var ids []string
	for _, c := range p.Checks {
		if !c.Passed {
			ids = append(ids, c.ID)
		}
	}
	return strings.Join(ids, ",")
}

func TestEvaluate_DecisionTable(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(f *Facts)
		rules    func(rs *types.AccessRuleSet)
		want     types.PostureState
		wantFail string
	}{
		{"healthy device is compliant", func(f *Facts) {}, nil, types.PostureCompliant, ""},
		{"never checked in", func(f *Facts) { f.LastCheckinAt = nil }, nil, types.PostureNoncompliant, "checkin_fresh"},
		{"stale check-in", func(f *Facts) { f.LastCheckinAt = ptrT(t0.Add(-25 * time.Hour)) }, nil, types.PostureNoncompliant, "checkin_fresh"},
		{"check-in exactly at limit passes", func(f *Facts) { f.LastCheckinAt = ptrT(t0.Add(-24 * time.Hour)) }, nil, types.PostureCompliant, ""},
		{"not approved", func(f *Facts) { f.Approved = false }, nil, types.PostureNoncompliant, CheckDeviceActive},
		{"lost", func(f *Facts) { f.Lost = true }, nil, types.PostureNoncompliant, CheckDeviceActive},
		{"attestation untrusted", func(f *Facts) { f.Trust = types.TrustEvaluation{Trusted: false, Reason: "stale"} }, nil, types.PostureNoncompliant, "attestation_trusted"},
		{"disk not reported fails", func(f *Facts) { f.DiskEncrypted = nil }, nil, types.PostureNoncompliant, "disk_encrypted"},
		{"disk unencrypted", func(f *Facts) { f.DiskEncrypted = ptrB(false) }, nil, types.PostureNoncompliant, "disk_encrypted"},
		{"policy non-compliant", func(f *Facts) {
			f.Policies = []PolicyFact{{"a", types.ComplianceNonCompliant}}
		}, nil, types.PostureNoncompliant, "policies_compliant"},
		{"policy failed", func(f *Facts) { f.Policies = []PolicyFact{{"a", types.ComplianceFailed}} }, nil, types.PostureNoncompliant, "policies_compliant"},
		{"pending policy passes by default", func(f *Facts) { f.Policies = []PolicyFact{{"a", types.CompliancePending}} }, nil, types.PostureCompliant, ""},
		{"pending policy fails when configured", func(f *Facts) { f.Policies = []PolicyFact{{"a", types.CompliancePending}} },
			func(rs *types.AccessRuleSet) { rs.PoliciesCompliant.PendingFails = true }, types.PostureNoncompliant, "policies_compliant"},
		{"revoked policy never counts", func(f *Facts) { f.Policies = []PolicyFact{{"a", types.ComplianceRevoked}} }, nil, types.PostureCompliant, ""},
		{"pending security updates", func(f *Facts) { f.Patch = &types.DevicePatchStatus{SecurityUpdatesCount: 2} }, nil, types.PostureNoncompliant, "patches_current"},
		{"no patch status reported", func(f *Facts) { f.Patch = nil }, nil, types.PostureNoncompliant, "patches_current"},
		{"pending updates but patched recently within grace", func(f *Facts) {
			f.Patch = &types.DevicePatchStatus{SecurityUpdatesCount: 2, LastPatchRunAt: ptrT(t0.Add(-48 * time.Hour)), LastPatchStatus: "SUCCESS"}
		}, func(rs *types.AccessRuleSet) { rs.PatchesCurrent.GraceDays = 7 }, types.PostureCompliant, ""},
		{"grace expired", func(f *Facts) {
			f.Patch = &types.DevicePatchStatus{SecurityUpdatesCount: 2, LastPatchRunAt: ptrT(t0.Add(-10 * 24 * time.Hour)), LastPatchStatus: "SUCCESS"}
		}, func(rs *types.AccessRuleSet) { rs.PatchesCurrent.GraceDays = 7 }, types.PostureNoncompliant, "patches_current"},
		{"grace but last patch failed", func(f *Facts) {
			f.Patch = &types.DevicePatchStatus{SecurityUpdatesCount: 2, LastPatchRunAt: ptrT(t0.Add(-time.Hour)), LastPatchStatus: "FAILED"}
		}, func(rs *types.AccessRuleSet) { rs.PatchesCurrent.GraceDays = 7 }, types.PostureNoncompliant, "patches_current"},
		{"high CVE open", func(f *Facts) { f.CVEs = []CVEFact{{ID: "CVE-1", Urgency: "high"}} }, nil, types.PostureNoncompliant, "no_critical_cves"},
		{"high CVE accepted", func(f *Facts) { f.CVEs = []CVEFact{{ID: "CVE-1", Urgency: "high", Accepted: true}} }, nil, types.PostureCompliant, ""},
		{"low CVE below threshold", func(f *Facts) { f.CVEs = []CVEFact{{ID: "CVE-2", Urgency: "low"}} }, nil, types.PostureCompliant, ""},
		{"low CVE at low threshold", func(f *Facts) { f.CVEs = []CVEFact{{ID: "CVE-2", Urgency: "low"}} },
			func(rs *types.AccessRuleSet) { rs.NoCriticalCVEs.MinUrgency = "low" }, types.PostureNoncompliant, "no_critical_cves"},
		{"unknown urgency is not counted", func(f *Facts) { f.CVEs = []CVEFact{{ID: "CVE-3", Urgency: "weird"}} }, nil, types.PostureCompliant, ""},
		{"group rule mismatch", func(f *Facts) { f.GroupRuleMatch = false }, nil, types.PostureNoncompliant, "group_rule"},
		{"quarantine overrides a healthy device", func(f *Facts) {
			f.Quarantine = &types.DeviceQuarantine{Reason: "malware", Actor: "alice"}
		}, nil, types.PostureQuarantined, ""},
		{"quarantine overrides failures", func(f *Facts) {
			f.Quarantine = &types.DeviceQuarantine{Reason: "malware", Actor: "alice"}
			f.DiskEncrypted = ptrB(false)
		}, nil, types.PostureQuarantined, "disk_encrypted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := healthy()
			if tc.mutate != nil {
				tc.mutate(&f)
			}
			rs := allOn()
			if tc.rules != nil {
				tc.rules(&rs)
			}
			p := Evaluate(f, rs, t0, 0)
			if p.State != tc.want {
				t.Fatalf("state = %s, want %s (reasons %v)", p.State, tc.want, p.Reasons)
			}
			if got := failedIDs(p); got != tc.wantFail {
				t.Fatalf("failed checks = %q, want %q", got, tc.wantFail)
			}
			if p.State == types.PostureCompliant && len(p.Reasons) != 0 {
				t.Fatalf("compliant verdict has reasons: %v", p.Reasons)
			}
			if p.State != types.PostureCompliant && len(p.Reasons) == 0 {
				t.Fatalf("%s verdict has no reasons", p.State)
			}
			if p.RuleSetVersion != 7 {
				t.Fatalf("rule set version = %d, want 7", p.RuleSetVersion)
			}
		})
	}
}

func TestEvaluate_DisabledChecksDoNotRun(t *testing.T) {
	// Only checkin_fresh is on (the fresh-install default): a device that fails every other
	// condition is still COMPLIANT, and no other check ids appear.
	f := Facts{DeviceID: "d", Approved: true, LastCheckinAt: ptrT(t0.Add(-time.Minute)), DiskEncrypted: ptrB(false)}
	p := Evaluate(f, types.DefaultAccessRuleSet(), t0, 0)
	if p.State != types.PostureCompliant {
		t.Fatalf("default rule set: state %s, reasons %v", p.State, p.Reasons)
	}
	for _, c := range p.Checks {
		if c.ID != CheckDeviceActive && c.ID != types.CheckCheckinFresh {
			t.Fatalf("disabled check %s ran", c.ID)
		}
	}
}

func TestEvaluate_ValidityWindow(t *testing.T) {
	p := Evaluate(healthy(), allOn(), t0, 0)
	if !p.ValidUntil.Equal(t0.Add(DefaultValidity)) {
		t.Fatalf("valid_until = %v, want %v", p.ValidUntil, t0.Add(DefaultValidity))
	}
	p2 := Evaluate(healthy(), allOn(), t0, 3*time.Minute)
	if !p2.ValidUntil.Equal(t0.Add(3 * time.Minute)) {
		t.Fatalf("custom validity ignored: %v", p2.ValidUntil)
	}
	// A stale verdict reads as UNKNOWN whatever its stored state (EffectiveState contract).
	if got := p.EffectiveState(t0.Add(DefaultValidity)); got != types.PostureUnknown {
		t.Fatalf("stale verdict effective state = %s, want UNKNOWN", got)
	}
	if got := p.EffectiveState(t0.Add(DefaultValidity - time.Second)); got != types.PostureCompliant {
		t.Fatalf("fresh verdict effective state = %s, want COMPLIANT", got)
	}
}

func TestUnknownOnError_NeverCompliant(t *testing.T) {
	p := UnknownOnError("d1", 3, "load_facts", t0, 0)
	if p.State != types.PostureUnknown || p.Allowed(t0) {
		t.Fatalf("error verdict must be UNKNOWN and not allowed, got %s", p.State)
	}
	if len(p.Reasons) != 1 || !strings.Contains(p.Reasons[0], "load_facts") {
		t.Fatalf("reasons = %v", p.Reasons)
	}
	if strings.Contains(strings.Join(p.Reasons, " "), "pq:") {
		t.Fatal("reasons must carry an error class, not raw error text")
	}
}

func TestSummarizeCaps(t *testing.T) {
	got := summarize([]string{"a", "b", "c", "d", "e"}, "thing")
	if !strings.Contains(got, "+2 more") || strings.Contains(got, "e") && !strings.Contains(got, "more") {
		t.Fatalf("summary = %q", got)
	}
}

func TestRuleSetNormalize(t *testing.T) {
	rs := types.AccessRuleSet{}
	rs.NoCriticalCVEs.Enabled = true
	rs.NoCriticalCVEs.MinUrgency = "bogus"
	if err := rs.Normalize(); err == nil {
		t.Fatal("bogus urgency accepted")
	}
	rs = types.AccessRuleSet{}
	rs.GroupRule.Enabled = true
	if err := rs.Normalize(); err == nil {
		t.Fatal("enabled group_rule without a rule accepted")
	}
	rs = types.AccessRuleSet{}
	rs.CheckinFresh.Enabled = true
	if err := rs.Normalize(); err != nil || rs.CheckinFresh.MaxAgeHours != 24 {
		t.Fatalf("default hours: %v %d", err, rs.CheckinFresh.MaxAgeHours)
	}
	rs.PatchesCurrent.GraceDays = -1
	if err := rs.Normalize(); err == nil {
		t.Fatal("negative grace accepted")
	}
}
