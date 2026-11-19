package campaign

// RollbackItemState classifies one package's rollback outcome plan.
type RollbackItemState string

const (
	// RollbackPlanned: the previous version is available; install it.
	RollbackPlanned RollbackItemState = "planned"
	// RollbackUnavailable: the previous version is no longer in the device's repositories.
	RollbackUnavailable RollbackItemState = "unavailable"
	// RollbackSkippedNotUpgraded: the campaign never upgraded this package, so it is NOT
	// touched (we never downgrade a package the campaign did not upgrade).
	RollbackSkippedNotUpgraded RollbackItemState = "skipped_not_upgraded"
	// RollbackNoPrevious: no previous version was recorded (nothing to roll back to).
	RollbackNoPrevious RollbackItemState = "no_previous"
)

// RollbackItem is one package's rollback plan.
type RollbackItem struct {
	Package     string            `json:"package"`
	FromVersion string            `json:"from_version,omitempty"` // version currently installed (post-upgrade)
	ToVersion   string            `json:"to_version,omitempty"`   // previous version to restore
	State       RollbackItemState `json:"state"`
}

// PlanRollback computes the rollback plan for a device. upgradedTo maps a package to the
// version the campaign installed (what is currently installed). previousVersions maps a
// package to the version installed BEFORE the campaign upgraded it. available reports whether
// a given package=version is installable from the device's repositories right now.
//
// Rules:
//   - A package the campaign did not upgrade (not in upgradedTo) is never touched.
//   - A package with no recorded previous version yields RollbackNoPrevious.
//   - If the previous version is available, plan to install it; otherwise mark unavailable.
//   - Never plan a target that is NEWER than or equal to the currently installed version
//     (that would not be a rollback); such a package is skipped as not-upgraded in effect.
func PlanRollback(upgradedTo, previousVersions map[string]string, available func(pkg, version string) bool) []RollbackItem {
	out := make([]RollbackItem, 0, len(upgradedTo))
	for pkg, cur := range upgradedTo {
		prev, ok := previousVersions[pkg]
		if !ok || prev == "" {
			out = append(out, RollbackItem{Package: pkg, FromVersion: cur, State: RollbackNoPrevious})
			continue
		}
		// The previous version must be strictly older than what is installed now, else it is
		// not a rollback.
		if cur != "" && !debianOlder(prev, cur) {
			out = append(out, RollbackItem{Package: pkg, FromVersion: cur, ToVersion: prev, State: RollbackSkippedNotUpgraded})
			continue
		}
		if !ValidPackageName(pkg) || !ValidVersion(prev) {
			out = append(out, RollbackItem{Package: pkg, FromVersion: cur, ToVersion: prev, State: RollbackUnavailable})
			continue
		}
		if available != nil && !available(pkg, prev) {
			out = append(out, RollbackItem{Package: pkg, FromVersion: cur, ToVersion: prev, State: RollbackUnavailable})
			continue
		}
		out = append(out, RollbackItem{Package: pkg, FromVersion: cur, ToVersion: prev, State: RollbackPlanned})
	}
	return out
}
