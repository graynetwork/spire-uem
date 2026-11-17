package campaign

import "testing"

func TestPlanRollback(t *testing.T) {
	upgraded := map[string]string{
		"curl":    "7.88.1-10+deb12u7", // upgraded; previous available
		"git":     "1:2.39.5-0+deb12u1", // upgraded; previous NOT available
		"openssl": "3.0.11",             // upgraded; no previous recorded
	}
	previous := map[string]string{
		"curl":  "7.88.1-10+deb12u5",
		"git":   "1:2.39.2-1.1",
		// openssl intentionally absent
		"nginx": "1.0", // not in upgraded -> must be ignored entirely
	}
	available := func(pkg, version string) bool {
		// Only curl's previous version is still available in the repo.
		return pkg == "curl" && version == "7.88.1-10+deb12u5"
	}

	plan := PlanRollback(upgraded, previous, available)
	byPkg := map[string]RollbackItem{}
	for _, it := range plan {
		byPkg[it.Package] = it
	}

	if byPkg["curl"].State != RollbackPlanned || byPkg["curl"].ToVersion != "7.88.1-10+deb12u5" {
		t.Errorf("curl should be planned to its available previous version: %+v", byPkg["curl"])
	}
	if byPkg["git"].State != RollbackUnavailable {
		t.Errorf("git previous version is not available -> unavailable, got %+v", byPkg["git"])
	}
	if byPkg["openssl"].State != RollbackNoPrevious {
		t.Errorf("openssl has no recorded previous -> no_previous, got %+v", byPkg["openssl"])
	}
	// A package the campaign never upgraded must NOT appear in the plan at all.
	if _, ok := byPkg["nginx"]; ok {
		t.Errorf("nginx was not upgraded by the campaign; it must never be downgraded")
	}
}

func TestPlanRollback_NeverDowngradeWhenPrevNotOlder(t *testing.T) {
	// If the "previous" version is not strictly older than what is installed (data drift),
	// do not plan a downgrade.
	upgraded := map[string]string{"curl": "7.0"}
	previous := map[string]string{"curl": "7.0"} // equal, not a rollback
	plan := PlanRollback(upgraded, previous, func(string, string) bool { return true })
	if len(plan) != 1 || plan[0].State != RollbackSkippedNotUpgraded {
		t.Errorf("equal previous version must not be rolled back, got %+v", plan)
	}
}

func TestPlanRollback_RejectsUnsafePreviousVersion(t *testing.T) {
	upgraded := map[string]string{"curl": "7.5"}
	previous := map[string]string{"curl": "7.0; rm -rf /"}
	plan := PlanRollback(upgraded, previous, func(string, string) bool { return true })
	if len(plan) != 1 || plan[0].State != RollbackUnavailable {
		t.Errorf("an unsafe previous version must never be planned, got %+v", plan)
	}
}
