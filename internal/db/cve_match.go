package db

import (
	"context"
	"strings"

	"github.com/spire-uem/spire-uem/internal/cvematch"
	"github.com/spire-uem/spire-uem/internal/types"
)

// RecomputeDeviceCVEsFromState matches one device's reported inventory against the imported
// feed and stores the result. Called incrementally on each check-in. It looks up CVE
// records only for the device's own source packages in its own release (one indexed query),
// so cost is proportional to that device's package count, not the whole feed.
//
// A device that reports no source packages or no release codename (older agent, or missing
// VERSION_CODENAME) has its matches cleared rather than guessed at.
func (r *Repository) RecomputeDeviceCVEsFromState(ctx context.Context, deviceID string, reported types.ReportedState) error {
	release := strings.ToLower(strings.TrimSpace(reported.ReleaseCodename))
	if release == "" || len(reported.SourcePackages) == 0 {
		return r.ReplaceDeviceCVEMatches(ctx, deviceID, nil)
	}

	// Collect the distinct source package names to look up.
	srcSet := make(map[string]struct{}, len(reported.SourcePackages))
	for _, p := range reported.SourcePackages {
		src := strings.TrimSpace(p.Source)
		if src == "" {
			src = strings.TrimSpace(p.Name)
		}
		if src != "" {
			srcSet[src] = struct{}{}
		}
	}
	sources := make([]string, 0, len(srcSet))
	for s := range srcSet {
		sources = append(sources, s)
	}

	index, err := r.GetCVEEntriesForSources(ctx, sources, release)
	if err != nil {
		return err
	}
	matches := cvematch.MatchDeviceCVEs(reported.SourcePackages, release, func(src string) []types.CVEEntry {
		return index[src]
	})
	return r.ReplaceDeviceCVEMatches(ctx, deviceID, matches)
}

// RecomputeAllDeviceCVEs recomputes matches for every approved device. Called after a feed
// import. It processes devices one at a time (each a bounded indexed lookup) to keep memory
// flat for 1000 devices x 2000 packages.
func (r *Repository) RecomputeAllDeviceCVEs(ctx context.Context) (int, error) {
	n := 0
	err := r.ForEachDeviceReportedState(ctx, func(deviceID string, reported types.ReportedState) error {
		if err := r.RecomputeDeviceCVEsFromState(ctx, deviceID, reported); err != nil {
			return err
		}
		n++
		return nil
	})
	return n, err
}
