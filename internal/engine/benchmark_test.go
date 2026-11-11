package engine

import (
	"context"
	"strings"
	"testing"
)

func TestParseBenchmarkResultsXML(t *testing.T) {
	sampleXML := `<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <TestResult id="xccdf_org.open-scap_testresult_default">
    <rule-result idref="xccdf_org.ssgproject.content_rule_sysctl_fs_protected_hardlinks" severity="medium">
      <result>pass</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sysctl_fs_protected_symlinks" severity="medium">
      <result>pass</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_partition_for_home" severity="low">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_partition_for_srv" severity="low">
      <result>notapplicable</result>
    </rule-result>
    <score system="urn:xccdf:scoring:default" maximum="100.000000">66.67</score>
  </TestResult>
</Benchmark>`

	payload, err := ParseBenchmarkResultsXML(strings.NewReader(sampleXML))
	if err != nil {
		t.Fatalf("ParseBenchmarkResultsXML failed: %v", err)
	}

	if payload.RulesPassed != 2 {
		t.Errorf("expected 2 passed rules, got %d", payload.RulesPassed)
	}
	if payload.RulesFailed != 1 {
		t.Errorf("expected 1 failed rule, got %d", payload.RulesFailed)
	}
	if payload.RulesOther != 1 {
		t.Errorf("expected 1 other rule, got %d", payload.RulesOther)
	}
	if payload.Score < 66.0 || payload.Score > 67.0 {
		t.Errorf("expected score ~66.67, got %.2f", payload.Score)
	}
	if len(payload.FailedRules) != 1 {
		t.Fatalf("expected 1 failed rule item, got %d", len(payload.FailedRules))
	}
	if payload.FailedRules[0].RuleID != "xccdf_org.ssgproject.content_rule_partition_for_home" {
		t.Errorf("unexpected RuleID: %s", payload.FailedRules[0].RuleID)
	}
	if payload.FailedRules[0].Severity != "low" {
		t.Errorf("unexpected Severity: %s", payload.FailedRules[0].Severity)
	}
	if payload.FailedRules[0].Title != "Partition for home" {
		t.Errorf("unexpected Title: %s", payload.FailedRules[0].Title)
	}
}

func TestRunBenchmarkScan_MissingOscap(t *testing.T) {
	// When oscap is absent or invalid path
	ctx := context.Background()
	_, err := RunBenchmarkScan(ctx, "nonexistent_profile", "/nonexistent/path.xml")
	if err == nil {
		t.Fatalf("expected error when running benchmark without valid oscap/datastream, got nil")
	}
}
