package cvematch

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// Debian Security Tracker JSON shape (https://security-tracker.debian.org/tracker/data/json):
//
//	{
//	  "<source package>": {
//	    "<CVE-id>": {
//	      "description": "...",
//	      "scope": "local|remote",
//	      "releases": {
//	        "<codename>": {
//	          "status": "resolved|open|undetermined",
//	          "repositories": {...},
//	          "fixed_version": "1.2.3-4",   // present when resolved
//	          "urgency": "high|medium|low|unimportant|not yet assigned",
//	          "nodsa": "...",
//	        }
//	      }
//	    }
//	  }
//	}
//
// The file is large (tens of MB). We decode it as a STREAM: one source-package object at
// a time via json.Decoder, invoking a callback per (package, CVE, release) record, so we
// never hold the whole decoded structure — nor the raw body — in memory twice.

type feedCVE struct {
	Description string                      `json:"description"`
	Scope       string                      `json:"scope"`
	Releases    map[string]feedReleaseEntry `json:"releases"`
}

type feedReleaseEntry struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
}

// StreamDebianFeed decodes the Debian Security Tracker JSON from r, calling emit once per
// (source package, CVE, release) record. It is streaming: the top-level object is read
// token by token and each source-package value is decoded and discarded before the next.
// It returns the number of records emitted.
//
// emit returning an error aborts the stream with that error (used so a DB batch failure
// stops the import).
func StreamDebianFeed(r io.Reader, emit func(types.CVEEntry) error) (int, error) {
	dec := json.NewDecoder(r)

	// Opening '{' of the top-level object.
	tok, err := dec.Token()
	if err != nil {
		return 0, fmt.Errorf("read feed opening token: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return 0, fmt.Errorf("feed is not a JSON object (got %v)", tok)
	}

	count := 0
	for dec.More() {
		// Key: the source package name.
		keyTok, err := dec.Token()
		if err != nil {
			return count, fmt.Errorf("read source package key: %w", err)
		}
		srcPkg, _ := keyTok.(string)

		// Value: a map of CVE id -> feedCVE, decoded as a single unit (one package's
		// worth of CVEs, which is small) and then released before the next package.
		var cves map[string]feedCVE
		if err := dec.Decode(&cves); err != nil {
			return count, fmt.Errorf("decode CVEs for %q: %w", srcPkg, err)
		}

		for cveID, cve := range cves {
			if !strings.HasPrefix(cveID, "CVE-") {
				continue // skip TEMP-/DLA-only grouping keys
			}
			for release, rel := range cve.Releases {
				status := normalizeStatus(rel.Status)
				entry := types.CVEEntry{
					SourcePackage: srcPkg,
					CVEID:         cveID,
					Release:       strings.ToLower(strings.TrimSpace(release)),
					Status:        status,
					FixedVersion:  strings.TrimSpace(rel.FixedVersion),
					Urgency:       strings.TrimSpace(rel.Urgency),
					Description:   strings.TrimSpace(cve.Description),
				}
				if err := emit(entry); err != nil {
					return count, err
				}
				count++
			}
		}
	}

	// Closing '}' — tolerate truncation only as an explicit error.
	if _, err := dec.Token(); err != nil && err != io.EOF {
		return count, fmt.Errorf("read feed closing token: %w", err)
	}
	return count, nil
}

// normalizeStatus maps the tracker's status strings onto our CVEFeedStatus enum.
func normalizeStatus(s string) types.CVEFeedStatus {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "resolved":
		return types.CVEStatusResolved
	case "open":
		return types.CVEStatusOpen
	default:
		return types.CVEStatusUndetermined
	}
}
