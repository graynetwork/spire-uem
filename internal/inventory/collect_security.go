package inventory

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// SecurityProductCatalogue is the FIXED list of security products the agent probes. The
// agent never reports a name outside this list, so the server's key catalogue is closed.
// Each entry maps the detection name to the systemd unit(s) whose active state means running.
var SecurityProductCatalogue = []struct {
	Name  string
	Units []string
}{
	{"clamav", []string{"clamav-daemon", "clamav-freshclam"}},
	{"wazuh-agent", []string{"wazuh-agent"}},
	{"falcon-sensor", []string{"falcon-sensor"}},
	{"mdatp", []string{"mdatp"}},
	{"elastic-agent", []string{"elastic-agent"}},
	{"sentinelone", []string{"sentinelone", "sentinelctl"}},
	{"osquery", []string{"osqueryd"}},
}

// collectSecurity probes the fixed product catalogue plus firewall/auditd/usbguard state.
func (c *Collector) collectSecurity(ctx context.Context) types.SecurityInfo {
	sec := types.SecurityInfo{}
	installed := c.installedPackageSet(ctx)
	for _, p := range SecurityProductCatalogue {
		prod := types.SecurityProduct{Name: p.Name, Installed: installed[p.Name]}
		for _, unit := range p.Units {
			if c.unitActive(ctx, unit) {
				prod.Running = true
				break
			}
		}
		if prod.Running {
			prod.Installed = true // running implies installed even if the dpkg name differs
		}
		// Always report an entry (installed or not) so the UI can show "not detected".
		sec.Products = append(sec.Products, prod)
	}
	sec.FirewallActive = c.firewallActive(ctx)
	sec.AuditdRunning = c.unitActive(ctx, "auditd")
	sec.USBGuardRunning = c.unitActive(ctx, "usbguard")
	return sec
}

// installedPackageSet returns the set of catalogue package names that dpkg reports installed.
func (c *Collector) installedPackageSet(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	status, err := c.run(ctx, "dpkg-query", "-W", "-f=${Package}\t${Status}\n")
	if err != nil && status == "" {
		// Fall back to reading /var/lib/dpkg/status directly from the (possibly fixture) root.
		return c.installedFromStatusFile()
	}
	wanted := catalogueNameSet()
	sc := bufio.NewScanner(strings.NewReader(status))
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		if wanted[name] && strings.Contains(fields[1], "installed") {
			out[name] = true
		}
	}
	return out
}

func (c *Collector) installedFromStatusFile() map[string]bool {
	out := map[string]bool{}
	f, err := os.Open(c.path("/var/lib/dpkg/status"))
	if err != nil {
		return out
	}
	defer f.Close()
	wanted := catalogueNameSet()
	var curName string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Package: ") {
			curName = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		} else if strings.HasPrefix(line, "Status: ") && wanted[curName] {
			if strings.Contains(line, "installed") && !strings.Contains(line, "not-installed") {
				out[curName] = true
			}
		}
	}
	return out
}

func catalogueNameSet() map[string]bool {
	s := make(map[string]bool, len(SecurityProductCatalogue))
	for _, p := range SecurityProductCatalogue {
		s[p.Name] = true
	}
	return s
}

// unitActive reports whether a systemd unit is active via `systemctl is-active <unit>`.
func (c *Collector) unitActive(ctx context.Context, unit string) bool {
	out, _ := c.run(ctx, "systemctl", "is-active", unit)
	return strings.TrimSpace(out) == "active"
}

// firewallActive reports whether an nftables ruleset is present (`nft list ruleset` prints
// at least one table). On a fixture root the runner provides canned output.
func (c *Collector) firewallActive(ctx context.Context) bool {
	out, err := c.run(ctx, "nft", "list", "ruleset")
	if err != nil && out == "" {
		return false
	}
	return strings.Contains(out, "table ")
}
