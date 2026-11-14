package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func TestValidateFirewallRulesetPayload(t *testing.T) {
	valid := types.FirewallRulesetPayload{
		DefaultInbound:   "drop",
		AllowEstablished: true,
		AllowLoopback:    true,
		InboundRules: []types.FirewallInboundRule{
			{Proto: "tcp", Port: 22, SourceCIDR: "10.0.0.0/8"},
			{Proto: "udp", Port: 51820},
			{Proto: "tcp", Port: 8000, PortEnd: 8010},
			{Proto: "tcp", Port: 443, SourceCIDR: "2001:db8::/32"},
		},
	}
	if err := ValidateFirewallRulesetPayload(valid); err != nil {
		t.Fatalf("expected valid payload, got: %v", err)
	}

	invalid := []types.FirewallRulesetPayload{
		{DefaultInbound: "allow"}, // bad default
		{DefaultInbound: "drop", InboundRules: []types.FirewallInboundRule{{Proto: "icmp", Port: 1}}},                            // bad proto
		{DefaultInbound: "drop", InboundRules: []types.FirewallInboundRule{{Proto: "tcp", Port: 0}}},                             // port range
		{DefaultInbound: "drop", InboundRules: []types.FirewallInboundRule{{Proto: "tcp", Port: 70000}}},                         // port range
		{DefaultInbound: "drop", InboundRules: []types.FirewallInboundRule{{Proto: "tcp", Port: 100, PortEnd: 50}}},              // end < start
		{DefaultInbound: "drop", InboundRules: []types.FirewallInboundRule{{Proto: "tcp", Port: 22, SourceCIDR: "999.0.0.0/8"}}}, // bad CIDR
		{DefaultInbound: "drop", InboundRules: []types.FirewallInboundRule{{Proto: "tcp", Port: 22, Comment: "bad\"quote"}}},     // bad comment
	}
	for i, p := range invalid {
		if err := ValidateFirewallRulesetPayload(p); err == nil {
			t.Errorf("case %d: expected validation error, got nil", i)
		}
	}
}

func TestRenderFirewallRuleset_Golden(t *testing.T) {
	p := types.FirewallRulesetPayload{
		DefaultInbound:   "drop",
		AllowEstablished: true,
		AllowLoopback:    true,
		AllowICMP:        true,
		InboundRules: []types.FirewallInboundRule{
			{Proto: "udp", Port: 51820, Comment: "wireguard"},
			{Proto: "tcp", Port: 22, SourceCIDR: "10.0.0.0/8"},
			{Proto: "tcp", Port: 8000, PortEnd: 8010},
		},
	}
	out, err := RenderFirewallRuleset(p)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	mustContain := []string{
		"table inet spire {",
		"type filter hook input priority 0; policy drop;",
		"iif lo accept",
		"ct state established,related accept",
		"ip protocol icmp accept",
		"ip6 nexthdr ipv6-icmp accept",
		"ip saddr 10.0.0.0/8 tcp dport 22 accept",
		"tcp dport 8000-8010 accept",
		"udp dport 51820 accept comment \"wireguard\"",
	}
	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Errorf("rendered ruleset missing %q.\nfull:\n%s", want, out)
		}
	}
	// Must never reference a table other than spire.
	if strings.Contains(out, "table inet filter") || strings.Contains(out, "flush ruleset") {
		t.Errorf("ruleset must not touch other tables or flush the whole ruleset:\n%s", out)
	}

	// Deterministic: rendering twice yields the same body (minus the timestamp comment line).
	out2, _ := RenderFirewallRuleset(p)
	strip := func(s string) string {
		var b strings.Builder
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "# Generated at:") {
				continue
			}
			b.WriteString(line + "\n")
		}
		return b.String()
	}
	if strip(out) != strip(out2) {
		t.Errorf("rendering is not deterministic")
	}
}

// fakeNft records the nft invocations and returns scripted results.
type fakeNft struct {
	calls      [][]string
	listOutput string
	listErr    error
	checkErr   error
	applyErr   error
}

func (f *fakeNft) run(ctx context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, args)
	switch {
	case len(args) >= 2 && args[0] == "-c" && args[1] == "-f":
		return "", f.checkErr
	case len(args) >= 1 && args[0] == "-f":
		return "", f.applyErr
	case len(args) >= 2 && args[0] == "list" && args[1] == "table":
		return f.listOutput, f.listErr
	case len(args) >= 1 && args[0] == "delete":
		return "", nil
	}
	return "", nil
}

func TestEnforceFirewallRuleset_ApplyVerifyDriftRemove(t *testing.T) {
	tmp := t.TempDir()
	origDir := nftRulesDir
	origRun := runNft
	nftRulesDir = filepath.Join(tmp, "etc/nftables.d")
	defer func() { nftRulesDir = origDir; runNft = origRun }()

	ctx := context.Background()
	payload := types.FirewallRulesetPayload{
		DefaultInbound:   "drop",
		AllowEstablished: true,
		AllowLoopback:    true,
		InboundRules: []types.FirewallInboundRule{
			{Proto: "tcp", Port: 22},
			{Proto: "tcp", Port: 443},
		},
	}
	pb, _ := json.Marshal(payload)
	pol := types.AssignedPolicy{ID: "fw-1", Name: "Baseline FW", PolicyType: types.PolicyTypeFirewallRuleset, Payload: pb}

	// 1. Happy path: live table matches -> COMPLIANT.
	fake := &fakeNft{listOutput: "table inet spire { chain input { type filter hook input priority 0; policy drop; tcp dport 22 accept tcp dport 443 accept } }"}
	runNft = fake.run
	item := EnforceFirewallRuleset(ctx, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("expected COMPLIANT, got %v (err=%s)", item.ComplianceStatus, item.ErrorMessage)
	}
	// File written, and nft called for -c then -f then list.
	if _, err := os.Stat(nftRulesPath()); err != nil {
		t.Fatalf("ruleset file not written: %v", err)
	}
	if len(fake.calls) < 3 || fake.calls[0][0] != "-c" || fake.calls[1][0] != "-f" || fake.calls[2][0] != "list" {
		t.Fatalf("expected nft -c, -f, list sequence, got %v", fake.calls)
	}

	// 2. Drift: live table missing port 443 -> NON_COMPLIANT.
	fakeDrift := &fakeNft{listOutput: "table inet spire { chain input { type filter hook input priority 0; policy drop; tcp dport 22 accept } }"}
	runNft = fakeDrift.run
	item = EnforceFirewallRuleset(ctx, pol)
	if item.ComplianceStatus != types.ComplianceNonCompliant {
		t.Fatalf("expected NON_COMPLIANT on drift, got %v", item.ComplianceStatus)
	}

	// 3. Flushed table: list errors -> NON_COMPLIANT.
	fakeFlushed := &fakeNft{listErr: context.Canceled}
	runNft = fakeFlushed.run
	item = EnforceFirewallRuleset(ctx, pol)
	if item.ComplianceStatus != types.ComplianceNonCompliant {
		t.Fatalf("expected NON_COMPLIANT when table flushed, got %v", item.ComplianceStatus)
	}

	// 4. nft -c rejects syntax -> FAILED.
	fakeBad := &fakeNft{checkErr: context.Canceled}
	runNft = fakeBad.run
	item = EnforceFirewallRuleset(ctx, pol)
	if item.ComplianceStatus != types.ComplianceFailed {
		t.Fatalf("expected FAILED when nft -c rejects, got %v", item.ComplianceStatus)
	}

	// 5. Removal deletes the file and issues a delete table.
	fakeRemove := &fakeNft{}
	runNft = fakeRemove.run
	if err := RemoveFirewallRuleset(ctx); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(nftRulesPath()); !os.IsNotExist(err) {
		t.Errorf("expected ruleset file removed, stat err=%v", err)
	}
	sawDelete := false
	for _, c := range fakeRemove.calls {
		if len(c) >= 1 && c[0] == "delete" {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Errorf("expected a delete table call on removal, got %v", fakeRemove.calls)
	}
}

func TestEnforceFirewallRuleset_InvalidPayload(t *testing.T) {
	ctx := context.Background()
	pol := types.AssignedPolicy{ID: "fw-bad", PolicyType: types.PolicyTypeFirewallRuleset, Payload: json.RawMessage(`{"default_inbound":"nonsense"}`)}
	item := EnforceFirewallRuleset(ctx, pol)
	if item.ComplianceStatus != types.ComplianceFailed {
		t.Fatalf("expected FAILED for invalid payload, got %v", item.ComplianceStatus)
	}
}
