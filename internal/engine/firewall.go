package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// Firewall engine: renders a dedicated `table inet spire` nftables ruleset, validates it with
// `nft -c -f`, applies it atomically with `nft -f`, and verifies by reading back the live table.
// It never touches any other nftables table and always leaves outbound traffic open so the agent
// keeps its connection to the control plane.

var (
	// nftRulesDir is the directory the spire ruleset file is written to. Overridden in tests.
	nftRulesDir = "/etc/nftables.d"
	// nftRulesFileName is the spire-owned ruleset file name.
	nftRulesFileName = "spire.nft"
	// findNftBin locates the nft binary. Overridden in tests with a fake.
	findNftBin = FindNftBinary
	// runNft executes nft with the given args and returns combined output. Overridden in tests.
	runNft = defaultRunNft
)

const (
	firewallTableName = "spire"
	firewallTableSpec = "table inet spire"
)

// FindNftBinary locates the nft executable in PATH or standard system directories.
func FindNftBinary() (string, error) {
	if p, err := exec.LookPath("nft"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("nft executable not found in PATH or standard directories")
}

// defaultRunNft runs nft with args and returns combined stdout+stderr.
func defaultRunNft(ctx context.Context, args ...string) (string, error) {
	bin, err := findNftBin()
	if err != nil {
		return "", err
	}
	out, runErr := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	return string(out), runErr
}

// validateFirewallPayload validates a FIREWALL_RULESET payload at the trust boundary.
// It is also used server-side so invalid CIDRs/ports are rejected before storage.
func validateFirewallPayload(p types.FirewallRulesetPayload) error {
	def := strings.ToLower(strings.TrimSpace(p.DefaultInbound))
	if def != "accept" && def != "drop" {
		return fmt.Errorf("default_inbound must be \"accept\" or \"drop\", got %q", p.DefaultInbound)
	}
	for i, r := range p.InboundRules {
		proto := strings.ToLower(strings.TrimSpace(r.Proto))
		if proto != "tcp" && proto != "udp" {
			return fmt.Errorf("inbound_rules[%d]: proto must be \"tcp\" or \"udp\", got %q", i, r.Proto)
		}
		if r.Port < 1 || r.Port > 65535 {
			return fmt.Errorf("inbound_rules[%d]: port %d out of range 1-65535", i, r.Port)
		}
		if r.PortEnd != 0 {
			if r.PortEnd < 1 || r.PortEnd > 65535 {
				return fmt.Errorf("inbound_rules[%d]: port_end %d out of range 1-65535", i, r.PortEnd)
			}
			if r.PortEnd < r.Port {
				return fmt.Errorf("inbound_rules[%d]: port_end %d must be >= port %d", i, r.PortEnd, r.Port)
			}
		}
		if cidr := strings.TrimSpace(r.SourceCIDR); cidr != "" {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("inbound_rules[%d]: invalid source_cidr %q: %w", i, cidr, err)
			}
		}
		if strings.ContainsAny(r.Comment, "\"\n\r{}\\") {
			return fmt.Errorf("inbound_rules[%d]: comment contains disallowed characters", i)
		}
	}
	return nil
}

// cidrFamily returns "ip" or "ip6" for an nftables saddr match, plus the normalized CIDR.
func cidrFamily(cidr string) (string, string, error) {
	ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return "", "", err
	}
	fam := "ip"
	if ip.To4() == nil {
		fam = "ip6"
	}
	return fam, ipnet.String(), nil
}

// RenderFirewallRuleset renders the deterministic nftables ruleset text for `table inet spire`.
// Rules are sorted for stable, golden-testable output.
func RenderFirewallRuleset(p types.FirewallRulesetPayload) (string, error) {
	if err := validateFirewallPayload(p); err != nil {
		return "", err
	}
	def := strings.ToLower(strings.TrimSpace(p.DefaultInbound))

	// Sort rules for deterministic rendering.
	rules := make([]types.FirewallInboundRule, len(p.InboundRules))
	copy(rules, p.InboundRules)
	sort.SliceStable(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.PortEnd != b.PortEnd {
			return a.PortEnd < b.PortEnd
		}
		return a.SourceCIDR < b.SourceCIDR
	})

	var sb strings.Builder
	sb.WriteString("# Managed by SpireUEM - FIREWALL_RULESET (table inet spire)\n")
	sb.WriteString(fmt.Sprintf("# Generated at: %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString("# Outbound is left unmanaged (open) and replies to established connections are always\n")
	sb.WriteString("# accepted, so the agent keeps its control-plane link whatever the inbound policy.\n")
	// Flush only our own table, then recreate it. This never references other tables.
	sb.WriteString("table inet spire\n")
	sb.WriteString("delete table inet spire\n")
	sb.WriteString("table inet spire {\n")
	sb.WriteString("\tchain input {\n")
	sb.WriteString(fmt.Sprintf("\t\ttype filter hook input priority 0; policy %s;\n", def))
	if p.AllowLoopback {
		sb.WriteString("\t\tiif lo accept\n")
	}
	// Always accept replies to established connections, regardless of AllowEstablished. The
	// agent's control-plane link is an outbound connection; with "policy drop" and no such rule
	// its reply packets would be dropped and the device could never be managed (or fixed) again.
	sb.WriteString("\t\tct state established,related accept\n")
	if p.AllowICMP {
		sb.WriteString("\t\tip protocol icmp accept\n")
		sb.WriteString("\t\tip6 nexthdr ipv6-icmp accept\n")
	}
	for _, r := range rules {
		proto := strings.ToLower(strings.TrimSpace(r.Proto))
		portExpr := fmt.Sprintf("%d", r.Port)
		if r.PortEnd != 0 && r.PortEnd != r.Port {
			portExpr = fmt.Sprintf("%d-%d", r.Port, r.PortEnd)
		}
		var line strings.Builder
		line.WriteString("\t\t")
		if cidr := strings.TrimSpace(r.SourceCIDR); cidr != "" {
			fam, norm, err := cidrFamily(cidr)
			if err != nil {
				return "", err
			}
			line.WriteString(fmt.Sprintf("%s saddr %s ", fam, norm))
		}
		line.WriteString(fmt.Sprintf("%s dport %s accept", proto, portExpr))
		if c := strings.TrimSpace(r.Comment); c != "" {
			line.WriteString(fmt.Sprintf(" comment \"%s\"", c))
		}
		line.WriteString("\n")
		sb.WriteString(line.String())
	}
	sb.WriteString("\t}\n")
	// Outbound/forward are intentionally omitted: we only manage the input chain of our own table.
	sb.WriteString("}\n")
	return sb.String(), nil
}

// nftRulesPath returns the full path of the spire ruleset file.
func nftRulesPath() string {
	return filepath.Join(nftRulesDir, nftRulesFileName)
}

// EnforceFirewallRuleset validates, writes, applies and verifies a FIREWALL_RULESET policy.
func EnforceFirewallRuleset(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	var payload types.FirewallRulesetPayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return failItem(policy.ID, fmt.Sprintf("invalid FIREWALL_RULESET payload: %v", err), nil)
	}

	ruleset, err := RenderFirewallRuleset(payload)
	if err != nil {
		return failItem(policy.ID, err.Error(), nil)
	}

	details := map[string]any{
		"policy_id": policy.ID,
		"table":     firewallTableSpec,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	if err := os.MkdirAll(nftRulesDir, 0755); err != nil {
		return failItem(policy.ID, fmt.Sprintf("mkdir %s: %v", nftRulesDir, err), details)
	}
	path := nftRulesPath()
	details["ruleset_path"] = path
	if err := atomicWriteFile(path, []byte(ruleset), 0644); err != nil {
		return failItem(policy.ID, fmt.Sprintf("write ruleset %s: %v", path, err), details)
	}

	// 1. Validate syntax with `nft -c -f <path>` (dry run) before applying.
	if out, err := runNft(ctx, "-c", "-f", path); err != nil {
		details["nft_check_output"] = strings.TrimSpace(out)
		return failItem(policy.ID, fmt.Sprintf("nft -c validation failed: %v", err), details)
	}

	// 2. Apply atomically with `nft -f <path>`.
	if out, err := runNft(ctx, "-f", path); err != nil {
		details["nft_apply_output"] = strings.TrimSpace(out)
		return failItem(policy.ID, fmt.Sprintf("nft -f apply failed: %v", err), details)
	}

	// 3. Verify by reading back the live table.
	readback, err := runNft(ctx, "list", "table", "inet", firewallTableName)
	if err != nil {
		details["nft_list_output"] = strings.TrimSpace(readback)
		// Table missing after apply: someone flushed it or apply silently did nothing -> drift.
		details["drifted"] = true
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceNonCompliant,
			ErrorMessage:     fmt.Sprintf("spire nftables table not present after apply: %v", err),
			ExecutionOutput:  mustJSON(details),
		}
	}

	if !firewallReadbackMatches(readback, payload) {
		details["drifted"] = true
		details["nft_list_output"] = strings.TrimSpace(readback)
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceNonCompliant,
			ErrorMessage:     "live spire nftables table does not match desired ruleset (drift detected and reasserted)",
			ExecutionOutput:  mustJSON(details),
		}
	}

	details["verified"] = true
	return types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  mustJSON(details),
	}
}

// firewallReadbackMatches checks that the live `nft list table inet spire` output contains the
// expected default policy and each desired dport rule. It is intentionally tolerant of nft's
// normalized formatting (whitespace, address families) while still catching a flushed/altered table.
func firewallReadbackMatches(readback string, p types.FirewallRulesetPayload) bool {
	flat := strings.Join(strings.Fields(readback), " ")
	def := strings.ToLower(strings.TrimSpace(p.DefaultInbound))
	if !strings.Contains(flat, "policy "+def) {
		return false
	}
	for _, r := range p.InboundRules {
		proto := strings.ToLower(strings.TrimSpace(r.Proto))
		portExpr := fmt.Sprintf("%d", r.Port)
		if r.PortEnd != 0 && r.PortEnd != r.Port {
			portExpr = fmt.Sprintf("%d-%d", r.Port, r.PortEnd)
		}
		if !strings.Contains(flat, fmt.Sprintf("%s dport %s", proto, portExpr)) {
			return false
		}
	}
	return true
}

// RemoveFirewallRuleset deletes the spire ruleset file and flushes the spire table, never touching
// any other nftables table. Used when a FIREWALL_RULESET policy is revoked.
func RemoveFirewallRuleset(ctx context.Context) error {
	path := nftRulesPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove ruleset %s: %w", path, err)
	}
	// Best-effort: delete only our own table. `delete table` is a no-op error if it does not exist.
	_, _ = runNft(ctx, "delete", "table", "inet", firewallTableName)
	return nil
}

// failItem builds a FAILED PolicyExecutionItem with optional details.
func failItem(policyID, msg string, details map[string]any) types.PolicyExecutionItem {
	var out []byte
	if details != nil {
		details["error"] = msg
		out = mustJSON(details)
	} else {
		out = mustJSON(map[string]any{"error": msg})
	}
	return types.PolicyExecutionItem{
		PolicyID:         policyID,
		ComplianceStatus: types.ComplianceFailed,
		ErrorMessage:     msg,
		ExecutionOutput:  out,
	}
}

// mustJSON marshals v, returning an empty object on failure.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// ValidateFirewallRulesetPayload is the exported trust-boundary validator, used by the server to
// reject invalid CIDRs/ports/protocols before a FIREWALL_RULESET policy is stored.
func ValidateFirewallRulesetPayload(p types.FirewallRulesetPayload) error {
	return validateFirewallPayload(p)
}
