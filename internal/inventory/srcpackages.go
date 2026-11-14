package inventory

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// maxReportedSourcePackages bounds the enriched package list sent on each check-in so
// the payload stays small even on a full desktop (a Debian desktop typically has a few
// thousand packages; each ReportedPackage is ~3 short strings). The cap is a safety
// valve: well under maxLargeBodyBytes on the server, and it never drops data silently
// without the server also still receiving the legacy flat Packages list.
const maxReportedSourcePackages = 6000

// dpkgSourceFormat asks dpkg-query for the binary name, the source package name and the
// SOURCE version. ${source:Version} already resolves to the binary version when a source
// version is not recorded separately, which is exactly the version Debian security data
// compares against. The three fields are tab-separated and newline-terminated.
const dpkgSourceFormat = "${Package}\t${source:Package}\t${source:Version}\t${Version}\n"

// GetSourcePackages runs dpkg-query with a source-aware format and returns the enriched
// per-package records used for CVE matching. The result is bounded by
// maxReportedSourcePackages. Malformed lines are skipped. ${source:Package} is empty for
// some packages; in that case the binary name is used as the source name, matching dpkg's
// own convention that an omitted Source means source name == binary name.
func GetSourcePackages() ([]types.ReportedPackage, error) {
	cmd := exec.Command("dpkg-query", "-W", "-f="+dpkgSourceFormat)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseSourcePackages(out), nil
}

// parseSourcePackages is the pure, testable core of GetSourcePackages.
func parseSourcePackages(out []byte) []types.ReportedPackage {
	var pkgs []types.ReportedPackage
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		bin := strings.TrimSpace(fields[0])
		src := strings.TrimSpace(fields[1])
		srcVer := strings.TrimSpace(fields[2])
		binVer := strings.TrimSpace(fields[3])
		if bin == "" {
			continue
		}
		// Strip any architecture qualifier dpkg may append to a multi-arch binary name
		// (e.g. "libc6:amd64") so the source name stays clean.
		if i := strings.IndexByte(bin, ':'); i > 0 {
			bin = bin[:i]
		}
		if src == "" {
			src = bin
		}
		// Debian's Source field can carry its own version in parentheses, e.g.
		// "openssl (3.0.11-1)". Prefer that explicit source version when present.
		if i := strings.IndexByte(src, ' '); i > 0 {
			rest := src[i+1:]
			src = strings.TrimSpace(src[:i])
			rest = strings.TrimSpace(strings.Trim(rest, "()"))
			if rest != "" {
				srcVer = rest
			}
		}
		ver := srcVer
		if ver == "" {
			ver = binVer
		}
		pkgs = append(pkgs, types.ReportedPackage{Name: bin, Source: src, SourceVersion: ver})
		if len(pkgs) >= maxReportedSourcePackages {
			break
		}
	}
	return pkgs
}

// GetReleaseCodename reads VERSION_CODENAME from /etc/os-release (falling back to
// /usr/lib/os-release). It returns "" when the field is absent, which the server treats
// as "unknown release" and skips CVE matching for that device rather than guessing.
func GetReleaseCodename() string {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if c := readCodename(p); c != "" {
			return c
		}
	}
	return ""
}

func readCodename(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		if k == "VERSION_CODENAME" {
			return strings.ToLower(strings.Trim(strings.TrimSpace(v), `"'`))
		}
	}
	return ""
}
