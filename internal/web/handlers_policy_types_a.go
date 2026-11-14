package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

// This file carries the server-side form parsing and trust-boundary validation for the policy-types-A
// declarative policies: FIREWALL_RULESET, LOCAL_ACCOUNT_POLICY and TRUSTED_CA_CERTIFICATES. The engine
// package owns the canonical validators (CIDR/port/cert parsing), which are reused here so the server
// rejects bad input before storage and the agent never has to enforce an invalid payload.

// buildFirewallRulesetPayload parses the FIREWALL_RULESET admin form into a validated JSON payload.
//
// Form fields:
//
//	fw_default_inbound   "accept" | "drop"
//	fw_allow_established  checkbox
//	fw_allow_loopback     checkbox
//	fw_allow_icmp         checkbox
//	fw_rules              one rule per line: "<tcp|udp> <port[-portEnd]> [source_cidr] [# comment]"
//	                      OR a raw JSON array of {proto,port,port_end,source_cidr,comment}
func buildFirewallRulesetPayload(r *http.Request) (json.RawMessage, error) {
	def := strings.ToLower(strings.TrimSpace(r.FormValue("fw_default_inbound")))
	if def == "" {
		def = "drop"
	}
	payload := types.FirewallRulesetPayload{
		DefaultInbound:   def,
		AllowEstablished: formBool(r, "fw_allow_established"),
		AllowLoopback:    formBool(r, "fw_allow_loopback"),
		AllowICMP:        formBool(r, "fw_allow_icmp"),
	}

	raw := strings.TrimSpace(r.FormValue("fw_rules"))
	if raw != "" {
		// Try JSON array first.
		var jsonRules []types.FirewallInboundRule
		if err := json.Unmarshal([]byte(raw), &jsonRules); err == nil {
			payload.InboundRules = jsonRules
		} else {
			parsed, perr := parseFirewallRuleLines(raw)
			if perr != nil {
				return nil, perr
			}
			payload.InboundRules = parsed
		}
	}

	if err := engine.ValidateFirewallRulesetPayload(payload); err != nil {
		return nil, fmt.Errorf("firewall ruleset invalid: %w", err)
	}
	return json.Marshal(payload)
}

// parseFirewallRuleLines parses the line-oriented rule syntax into structured rules.
func parseFirewallRuleLines(raw string) ([]types.FirewallInboundRule, error) {
	var rules []types.FirewallInboundRule
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		comment := ""
		if idx := strings.Index(line, "#"); idx >= 0 {
			comment = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("rule line %d: expected at least \"<proto> <port>\", got %q", i+1, line)
		}
		rule := types.FirewallInboundRule{
			Proto:   strings.ToLower(fields[0]),
			Comment: comment,
		}
		portField := fields[1]
		if dash := strings.Index(portField, "-"); dash >= 0 {
			start, err1 := strconv.Atoi(strings.TrimSpace(portField[:dash]))
			end, err2 := strconv.Atoi(strings.TrimSpace(portField[dash+1:]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("rule line %d: invalid port range %q", i+1, portField)
			}
			rule.Port = start
			rule.PortEnd = end
		} else {
			p, err := strconv.Atoi(portField)
			if err != nil {
				return nil, fmt.Errorf("rule line %d: invalid port %q", i+1, portField)
			}
			rule.Port = p
		}
		if len(fields) >= 3 {
			cidr := strings.TrimSpace(fields[2])
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return nil, fmt.Errorf("rule line %d: invalid source CIDR %q: %w", i+1, cidr, err)
			}
			rule.SourceCIDR = cidr
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// buildLocalAccountPolicyPayload parses the LOCAL_ACCOUNT_POLICY admin form into a validated payload.
//
// Form fields: la_minlen, la_minclass, la_faillock_deny, la_faillock_unlock, la_pass_max_days,
// la_sudo_groups (comma/space list), la_sudo_users (comma/space list), la_sudo_nopasswd (checkbox).
func buildLocalAccountPolicyPayload(r *http.Request) (json.RawMessage, error) {
	payload := types.LocalAccountPolicyPayload{
		PwqualityMinLen:    formInt(r, "la_minlen"),
		PwqualityMinClass:  formInt(r, "la_minclass"),
		FaillockDeny:       formInt(r, "la_faillock_deny"),
		FaillockUnlockTime: formInt(r, "la_faillock_unlock"),
		PassMaxDays:        formInt(r, "la_pass_max_days"),
	}
	groups := splitList(r.FormValue("la_sudo_groups"))
	users := splitList(r.FormValue("la_sudo_users"))
	if len(groups) > 0 || len(users) > 0 || formBool(r, "la_sudo_nopasswd") {
		payload.Sudoers = &types.LocalAccountSudoersPayload{
			Groups:   groups,
			Users:    users,
			NoPasswd: formBool(r, "la_sudo_nopasswd"),
		}
	}

	// Require at least one managed knob so an empty policy is not silently created.
	if payload.PwqualityMinLen == 0 && payload.PwqualityMinClass == 0 &&
		payload.FaillockDeny == 0 && payload.FaillockUnlockTime == 0 &&
		payload.PassMaxDays == 0 && payload.Sudoers == nil {
		return nil, fmt.Errorf("LOCAL_ACCOUNT_POLICY requires at least one setting (password quality, lockout, max age, or sudoers)")
	}

	if err := engine.ValidateLocalAccountPolicyPayload(payload); err != nil {
		return nil, fmt.Errorf("local account policy invalid: %w", err)
	}
	return json.Marshal(payload)
}

// buildTrustedCACertificatesPayload parses the TRUSTED_CA_CERTIFICATES admin form.
//
// Form fields: ca_certs — a raw JSON array of {name,pem}, OR ca_name + ca_pem for a single cert.
func buildTrustedCACertificatesPayload(r *http.Request) (json.RawMessage, error) {
	var payload types.TrustedCACertificatesPayload

	raw := strings.TrimSpace(r.FormValue("ca_certs"))
	if raw != "" {
		var certs []types.TrustedCACertificate
		if err := json.Unmarshal([]byte(raw), &certs); err != nil {
			return nil, fmt.Errorf("ca_certs must be a JSON array of {name,pem}: %w", err)
		}
		payload.Certificates = certs
	} else {
		name := strings.TrimSpace(r.FormValue("ca_name"))
		pemText := strings.TrimSpace(r.FormValue("ca_pem"))
		if name == "" || pemText == "" {
			return nil, fmt.Errorf("ca_name and ca_pem are required for TRUSTED_CA_CERTIFICATES")
		}
		payload.Certificates = []types.TrustedCACertificate{{Name: name, PEM: pemText}}
	}

	// Validate each cert parses as a CA (engine owns the canonical parser).
	if err := engine.ValidateTrustedCAPayload(payload); err != nil {
		return nil, fmt.Errorf("trusted CA certificates invalid: %w", err)
	}
	return json.Marshal(payload)
}

// formBool reads a checkbox-style form value.
func formBool(r *http.Request, field string) bool {
	v := strings.ToLower(strings.TrimSpace(r.FormValue(field)))
	return v == "true" || v == "1" || v == "on" || v == "yes"
}

// formInt reads an optional integer form value, returning 0 when empty/unset.
func formInt(r *http.Request, field string) int {
	v := strings.TrimSpace(r.FormValue(field))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

// splitList splits a comma/space/newline separated list, trimming and de-duping entries.
func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(c rune) bool {
		return c == ',' || c == ' ' || c == '\n' || c == '\t' || c == '\r'
	})
	seen := make(map[string]bool, len(fields))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}
