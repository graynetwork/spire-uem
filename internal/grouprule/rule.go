// Package grouprule models the JSON rule tree of a dynamic device group and compiles it to
// parameterised SQL against the devices/device_attributes/device_cve_matches/device_policies
// tables.
//
// SECURITY: every field name in the generated SQL comes from a FIXED allowlist of SQL
// fragments; no user- or agent-supplied string is ever concatenated into SQL text. All
// values (and attribute keys) are bound parameters. Unknown fields, operator/type mismatches
// and malformed values are rejected at validation time with a clear error, before any SQL is
// built. Depth and leaf count are bounded so a hostile rule cannot blow up the planner.
package grouprule

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	// MaxDepth bounds rule-tree nesting (all/any/not combinators).
	MaxDepth = 6
	// MaxLeaves bounds the number of leaf conditions in one rule.
	MaxLeaves = 64
	// MaxRegexLen caps a regex value so a pathological pattern cannot be stored.
	MaxRegexLen = 256
	// MaxStringLen caps a string/in value length.
	MaxStringLen = 512
	// MaxInValues caps the element count of an `in` list.
	MaxInValues = 128
)

// valueKind is the declared type family a field evaluates as.
type valueKind string

const (
	kindString   valueKind = "string"
	kindNumber   valueKind = "number"
	kindBool     valueKind = "boolean"
	kindDatetime valueKind = "datetime"
	kindTags     valueKind = "tags"
	kindVersion  valueKind = "version" // agent_version: compared in Go, not SQL
)

// fieldDef describes one allow-listed device field: the SQL expression that yields its value
// and the type family that governs which operators are legal. sqlExpr is a trusted constant.
type fieldDef struct {
	sqlExpr string
	kind    valueKind
	// existsExpr, when set, is a boolean SQL expression that is true when the field "exists"
	// for a device (used by the exists/missing operators). Defaults to "sqlExpr IS NOT NULL".
	existsExpr string
}

// deviceFields is the fixed allowlist of built-in device fields. The SQL fragments reference
// the devices row aliased `d` and LEFT JOINed patch-status aliased `ps`. These are compiled
// constants — never built from input.
var deviceFields = map[string]fieldDef{
	"device.hostname":           {sqlExpr: "d.hostname", kind: kindString},
	"device.status":             {sqlExpr: "d.status::text", kind: kindString},
	"device.tags":               {sqlExpr: "d.tags", kind: kindTags},
	"device.patch_ring":         {sqlExpr: "d.patch_ring::text", kind: kindString},
	"device.agent_version":      {sqlExpr: "d.agent_version", kind: kindVersion},
	"device.last_checkin_at":    {sqlExpr: "d.last_checkin_at", kind: kindDatetime},
	"device.attestation_status": {sqlExpr: "d.attestation_status::text", kind: kindString},
	"device.os_name":            {sqlExpr: "(d.reported_state->>'os_name')", kind: kindString},
	"device.kernel_version":     {sqlExpr: "(d.reported_state->>'kernel_version')", kind: kindString},
	"device.release_codename":   {sqlExpr: "(d.reported_state->>'release_codename')", kind: kindString},
	"device.pending_updates":    {sqlExpr: "COALESCE(ps.pending_updates_count, 0)", kind: kindNumber},
	"device.security_updates":   {sqlExpr: "COALESCE(ps.security_updates_count, 0)", kind: kindNumber},
	"device.reboot_required":    {sqlExpr: "COALESCE(ps.reboot_required, d.reboot_required)", kind: kindBool},
	"device.ws_connected":       {sqlExpr: "d.ws_connected", kind: kindBool},
	// compliance: true when the device has at least one non-compliant REQUIRED active policy.
	"device.compliance": {
		sqlExpr: `EXISTS (
			SELECT 1 FROM device_policies dpc
			JOIN policies pc ON pc.id = dpc.policy_id
			WHERE dpc.device_id = d.id
			  AND dpc.compliance_status IN ('NON_COMPLIANT','FAILED')
			  AND pc.is_active = true
			  AND COALESCE(pc.assignment_type,'REQUIRED') = 'REQUIRED'
			  AND pc.is_self_service = false
		)`,
		kind: kindBool,
	},
	// cve.id: true when the device has any open CVE match.
	"cve.id": {
		sqlExpr:    `EXISTS (SELECT 1 FROM device_cve_matches dcm WHERE dcm.device_id = d.id)`,
		kind:       kindBool,
		existsExpr: `EXISTS (SELECT 1 FROM device_cve_matches dcm WHERE dcm.device_id = d.id)`,
	},
	// cve.open_high_or_critical: count of open high-urgency CVE matches for the device.
	"cve.open_high_or_critical": {
		sqlExpr: `(SELECT COUNT(*) FROM device_cve_matches dcm
			WHERE dcm.device_id = d.id
			  AND dcm.urgency IN ('high','high**')
			  AND dcm.no_fix_available = false)`,
		kind: kindNumber,
	},
}

// Operator families.
var (
	stringOps   = map[string]bool{"eq": true, "ne": true, "contains": true, "starts_with": true, "in": true, "matches": true, "exists": true, "missing": true}
	numberOps   = map[string]bool{"eq": true, "ne": true, "lt": true, "lte": true, "gt": true, "gte": true, "in": true, "exists": true, "missing": true}
	boolOps     = map[string]bool{"eq": true, "exists": true, "missing": true}
	datetimeOps = map[string]bool{"before": true, "after": true, "older_than": true, "newer_than": true, "exists": true, "missing": true}
	tagsOps     = map[string]bool{"contains_any": true, "contains_all": true, "exists": true, "missing": true}
	versionOps  = map[string]bool{"eq": true, "ne": true, "lt": true, "lte": true, "gt": true, "gte": true, "exists": true, "missing": true}
	// attrOps is the union of scalar operators; attr.<key> fields accept any of them and the
	// concrete comparison type is derived from the bound value's JSON shape at compile time.
	attrOps = func() map[string]bool {
		m := map[string]bool{}
		for _, src := range []map[string]bool{stringOps, numberOps, boolOps, datetimeOps} {
			for k := range src {
				m[k] = true
			}
		}
		return m
	}()
)

func opsFor(k valueKind) map[string]bool {
	switch k {
	case kindString:
		return stringOps
	case kindNumber:
		return numberOps
	case kindBool:
		return boolOps
	case kindDatetime:
		return datetimeOps
	case kindTags:
		return tagsOps
	case kindVersion:
		return versionOps
	case attrKind:
		return attrOps
	}
	return nil
}

// node is a parsed rule tree node: exactly one of the combinator fields or a leaf is set.
type node struct {
	All  []node
	Any  []node
	Not  *node
	Leaf *leaf
}

type leaf struct {
	Field string
	Op    string
	Value json.RawMessage
}

// rawNode is the wire shape of a rule node. A node is a combinator ({"all":[...]},
// {"any":[...]}, {"not":{...}}) or a leaf ({"field":...,"op":...,"value":...}).
type rawNode struct {
	All   []json.RawMessage `json:"all"`
	Any   []json.RawMessage `json:"any"`
	Not   json.RawMessage   `json:"not"`
	Field string            `json:"field"`
	Op    string            `json:"op"`
	Value json.RawMessage   `json:"value"`
}

var attrKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`)

// ValidationError is a rule validation failure with a human-readable reason.
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func verr(format string, a ...any) *ValidationError {
	return &ValidationError{msg: fmt.Sprintf(format, a...)}
}

// IsValidationError reports whether err is a rule validation error (as opposed to an internal
// error), so handlers can map it to 400 rather than 500.
func IsValidationError(err error) bool {
	_, ok := err.(*ValidationError)
	return ok
}

// Parse decodes and validates a rule tree. A nil or empty raw rule is valid and yields a nil
// compiled rule (a group with no rule). The regex validator, when non-nil, is called for
// every `matches` pattern so Postgres can confirm the pattern compiles before it is stored.
func Parse(raw json.RawMessage, regexValidator func(pattern string) error) (*Rule, error) {
	trimmed := strings.TrimSpace(string(raw))
	if len(raw) == 0 || trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	p := &parser{regexValidator: regexValidator}
	root, err := p.parseNode(raw, 1)
	if err != nil {
		return nil, err
	}
	if p.leaves == 0 {
		return nil, verr("rule has no conditions")
	}
	return &Rule{root: root}, nil
}

type parser struct {
	leaves         int
	regexValidator func(string) error
}

func (p *parser) parseNode(raw json.RawMessage, depth int) (node, error) {
	if depth > MaxDepth {
		return node{}, verr("rule nesting exceeds the limit of %d", MaxDepth)
	}
	var rn rawNode
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rn); err != nil {
		return node{}, verr("invalid rule node: %v", err)
	}

	// Exactly one of all / any / not / leaf.
	set := 0
	if rn.All != nil {
		set++
	}
	if rn.Any != nil {
		set++
	}
	if len(rn.Not) > 0 {
		set++
	}
	isLeaf := rn.Field != "" || rn.Op != "" || len(rn.Value) > 0
	if isLeaf {
		set++
	}
	if set == 0 {
		return node{}, verr("empty rule node: expected one of all, any, not or a leaf")
	}
	if set > 1 {
		return node{}, verr("rule node must be exactly one of all, any, not or a leaf")
	}

	switch {
	case rn.All != nil:
		if len(rn.All) == 0 {
			return node{}, verr("`all` must have at least one condition")
		}
		n := node{All: make([]node, 0, len(rn.All))}
		for _, c := range rn.All {
			child, err := p.parseNode(c, depth+1)
			if err != nil {
				return node{}, err
			}
			n.All = append(n.All, child)
		}
		return n, nil
	case rn.Any != nil:
		if len(rn.Any) == 0 {
			return node{}, verr("`any` must have at least one condition")
		}
		n := node{Any: make([]node, 0, len(rn.Any))}
		for _, c := range rn.Any {
			child, err := p.parseNode(c, depth+1)
			if err != nil {
				return node{}, err
			}
			n.Any = append(n.Any, child)
		}
		return n, nil
	case len(rn.Not) > 0:
		child, err := p.parseNode(rn.Not, depth+1)
		if err != nil {
			return node{}, err
		}
		return node{Not: &child}, nil
	default:
		lf, err := p.parseLeaf(rn)
		if err != nil {
			return node{}, err
		}
		return node{Leaf: lf}, nil
	}
}

func (p *parser) parseLeaf(rn rawNode) (*leaf, error) {
	p.leaves++
	if p.leaves > MaxLeaves {
		return nil, verr("rule exceeds the limit of %d conditions", MaxLeaves)
	}
	field := strings.TrimSpace(rn.Field)
	op := strings.TrimSpace(rn.Op)
	if field == "" {
		return nil, verr("leaf is missing a field")
	}
	if op == "" {
		return nil, verr("leaf for field %q is missing an operator", field)
	}

	kind, _, err := resolveField(field)
	if err != nil {
		return nil, err
	}
	if !opsFor(kind)[op] {
		return nil, verr("operator %q is not valid for field %q", op, field)
	}
	// exists/missing take no value; everything else requires one.
	if op == "exists" || op == "missing" {
		if len(rn.Value) > 0 && strings.TrimSpace(string(rn.Value)) != "null" {
			return nil, verr("operator %q on %q takes no value", op, field)
		}
		return &leaf{Field: field, Op: op}, nil
	}
	if len(rn.Value) == 0 {
		return nil, verr("operator %q on %q requires a value", op, field)
	}
	if err := p.validateValue(field, kind, op, rn.Value); err != nil {
		return nil, err
	}
	return &leaf{Field: field, Op: op, Value: rn.Value}, nil
}

// resolveField returns the value kind and field definition for a field name, resolving
// attr.<key> dynamically. attr fields default to string-family operators (their declared
// attribute type is enforced at value level via JSON casts in compilation).
func resolveField(field string) (valueKind, *fieldDef, error) {
	if strings.HasPrefix(field, "attr.") {
		key := strings.TrimPrefix(field, "attr.")
		if !attrKeyRe.MatchString(key) || len(key) > 128 {
			return "", nil, verr("invalid attribute key in field %q", field)
		}
		// Attribute kind is resolved per-operator in the leaf (see validateValue/compileLeaf):
		// the attribute's stored type governs the comparison. We return a sentinel kind that
		// accepts the union of operators; the concrete type is enforced by the value check.
		return attrKind, nil, nil
	}
	fd, ok := deviceFields[field]
	if !ok {
		return "", nil, verr("unknown field %q", field)
	}
	return fd.kind, &fd, nil
}

// attrKind is a pseudo-kind for attr.<key> fields; the operator set is the union and the
// concrete comparison type is derived from the value's JSON shape at validation time.
const attrKind valueKind = "attr"

// FieldInfo describes one selectable rule field for the UI builder.
type FieldInfo struct {
	Name string   `json:"name"`
	Kind string   `json:"kind"`
	Ops  []string `json:"ops"`
}

// Fields returns the fixed allowlist of built-in device/CVE fields with their legal
// operators, for rendering the rule-builder UI. attr.<key> fields are added dynamically from
// the live attribute keys and are not listed here.
func Fields() []FieldInfo {
	order := []string{
		"device.hostname", "device.status", "device.tags", "device.patch_ring",
		"device.agent_version", "device.last_checkin_at", "device.attestation_status",
		"device.os_name", "device.kernel_version", "device.release_codename",
		"device.pending_updates", "device.security_updates", "device.reboot_required",
		"device.ws_connected", "device.compliance", "cve.id", "cve.open_high_or_critical",
	}
	out := make([]FieldInfo, 0, len(order))
	for _, name := range order {
		fd := deviceFields[name]
		ops := make([]string, 0, len(opsFor(fd.kind)))
		for op := range opsFor(fd.kind) {
			ops = append(ops, op)
		}
		out = append(out, FieldInfo{Name: name, Kind: string(fd.kind), Ops: ops})
	}
	return out
}

// validateValue checks the JSON value against the operator and kind, and (for matches) that
// the regex compiles in Postgres. For attr fields the concrete type is inferred from the
// operator chosen and the JSON value shape.
func (p *parser) validateValue(field string, kind valueKind, op string, raw json.RawMessage) error {
	switch op {
	case "in":
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return verr("value for %q %q must be an array", field, op)
		}
		if len(arr) == 0 {
			return verr("`in` list for %q is empty", field)
		}
		if len(arr) > MaxInValues {
			return verr("`in` list for %q exceeds %d values", field, MaxInValues)
		}
		for _, el := range arr {
			if err := p.validateScalar(field, kind, el); err != nil {
				return err
			}
		}
		return nil
	case "contains_any", "contains_all":
		var arr []string
		if err := json.Unmarshal(raw, &arr); err != nil {
			return verr("value for %q %q must be an array of strings", field, op)
		}
		if len(arr) == 0 {
			return verr("tag list for %q is empty", field)
		}
		if len(arr) > MaxInValues {
			return verr("tag list for %q exceeds %d values", field, MaxInValues)
		}
		for _, s := range arr {
			if len(s) > MaxStringLen {
				return verr("tag value too long in %q", field)
			}
		}
		return nil
	case "matches":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return verr("regex value for %q must be a string", field)
		}
		if s == "" {
			return verr("empty regex for %q", field)
		}
		if len(s) > MaxRegexLen {
			return verr("regex for %q exceeds %d characters", field, MaxRegexLen)
		}
		if p.regexValidator != nil {
			if err := p.regexValidator(s); err != nil {
				return verr("invalid POSIX regex for %q: %v", field, err)
			}
		}
		return nil
	case "older_than", "newer_than":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return verr("duration value for %q must be a string like \"7d\" or \"12h\"", field)
		}
		if _, err := ParseDuration(s); err != nil {
			return verr("invalid duration for %q: %v", field, err)
		}
		return nil
	default:
		return p.validateScalar(field, kind, raw)
	}
}

// validateScalar checks a single scalar value against the field kind.
func (p *parser) validateScalar(field string, kind valueKind, raw json.RawMessage) error {
	switch kind {
	case kindString, kindVersion:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return verr("value for %q must be a string", field)
		}
		if len(s) > MaxStringLen {
			return verr("string value for %q too long", field)
		}
		return nil
	case kindNumber:
		var n json.Number
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.UseNumber()
		if err := d.Decode(&n); err != nil {
			return verr("value for %q must be a number", field)
		}
		if _, err := n.Float64(); err != nil {
			return verr("value for %q must be a number", field)
		}
		return nil
	case kindBool:
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return verr("value for %q must be a boolean", field)
		}
		return nil
	case kindDatetime:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return verr("datetime value for %q must be an RFC 3339 string", field)
		}
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return verr("datetime value for %q must be RFC 3339", field)
		}
		return nil
	case attrKind:
		// attr value may be string, number or boolean; we accept any scalar JSON and bind it
		// with the appropriate cast at compile time based on its JSON shape.
		var any interface{}
		if err := json.Unmarshal(raw, &any); err != nil {
			return verr("invalid value for %q", field)
		}
		switch any.(type) {
		case string, float64, bool, json.Number:
			return nil
		default:
			return verr("attribute value for %q must be a string, number or boolean", field)
		}
	}
	return verr("unsupported value kind for %q", field)
}
