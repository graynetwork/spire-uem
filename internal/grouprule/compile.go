package grouprule

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Rule is a validated, compiled group rule.
type Rule struct {
	root node
}

func (r *Rule) marshalNode(n node) any {
	switch {
	case n.All != nil:
		arr := make([]any, len(n.All))
		for i, c := range n.All {
			arr[i] = r.marshalNode(c)
		}
		return map[string]any{"all": arr}
	case n.Any != nil:
		arr := make([]any, len(n.Any))
		for i, c := range n.Any {
			arr[i] = r.marshalNode(c)
		}
		return map[string]any{"any": arr}
	case n.Not != nil:
		return map[string]any{"not": r.marshalNode(*n.Not)}
	default:
		m := map[string]any{"field": n.Leaf.Field, "op": n.Leaf.Op}
		if len(n.Leaf.Value) > 0 {
			m["value"] = json.RawMessage(n.Leaf.Value)
		}
		return m
	}
}

// Normalized returns the rule as canonical JSON (for storage).
func (r *Rule) Normalized() (json.RawMessage, error) {
	b, err := json.Marshal(r.marshalNode(r.root))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// compileCtx accumulates bind parameters while building SQL.
type compileCtx struct {
	args    []any
	startAt int
}

func (c *compileCtx) bind(v any) string {
	c.args = append(c.args, v)
	return "$" + strconv.Itoa(c.startAt+len(c.args)-1)
}

// Compile renders the rule to a boolean SQL predicate over the devices row aliased `d` and
// the LEFT JOINed device_patch_status aliased `ps`, plus the bind parameters. startAt is the
// 1-based index of the first placeholder this predicate may use, so it composes with a
// caller's existing parameters. The SQL references ONLY allow-listed field fragments; every
// value and attribute key is a bound parameter — no input is ever concatenated into SQL.
func (r *Rule) Compile(startAt int) (sql string, args []any, err error) {
	c := &compileCtx{startAt: startAt}
	s, err := r.compileNode(r.root, c)
	if err != nil {
		return "", nil, err
	}
	return s, c.args, nil
}

func (r *Rule) compileNode(n node, c *compileCtx) (string, error) {
	switch {
	case n.All != nil:
		parts := make([]string, 0, len(n.All))
		for _, ch := range n.All {
			s, err := r.compileNode(ch, c)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "(" + strings.Join(parts, " AND ") + ")", nil
	case n.Any != nil:
		parts := make([]string, 0, len(n.Any))
		for _, ch := range n.Any {
			s, err := r.compileNode(ch, c)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "(" + strings.Join(parts, " OR ") + ")", nil
	case n.Not != nil:
		s, err := r.compileNode(*n.Not, c)
		if err != nil {
			return "", err
		}
		return "(NOT " + s + ")", nil
	default:
		return r.compileLeaf(n.Leaf, c)
	}
}

func (r *Rule) compileLeaf(lf *leaf, c *compileCtx) (string, error) {
	if strings.HasPrefix(lf.Field, "attr.") {
		return r.compileAttrLeaf(lf, c)
	}
	fd, ok := deviceFields[lf.Field]
	if !ok {
		return "", fmt.Errorf("compile: unknown field %q", lf.Field)
	}
	expr := fd.sqlExpr

	switch lf.Op {
	case "exists":
		if fd.existsExpr != "" {
			return "(" + fd.existsExpr + ")", nil
		}
		return "(" + expr + " IS NOT NULL)", nil
	case "missing":
		if fd.existsExpr != "" {
			return "(NOT " + fd.existsExpr + ")", nil
		}
		return "(" + expr + " IS NULL)", nil
	}

	switch fd.kind {
	case kindString:
		return compileStringOp(expr, lf.Op, lf.Value, c)
	case kindNumber:
		return compileNumberOp(expr, lf.Op, lf.Value, c)
	case kindBool:
		return compileBoolOp(expr, lf.Op, lf.Value, c)
	case kindDatetime:
		return compileDatetimeOp(expr, lf.Op, lf.Value, c)
	case kindTags:
		return compileTagsOp(expr, lf.Op, lf.Value, c)
	case kindVersion:
		return compileVersionOp(expr, lf.Op, lf.Value, c)
	}
	return "", fmt.Errorf("compile: unsupported field kind for %q", lf.Field)
}

func compileStringOp(expr, op string, raw json.RawMessage, c *compileCtx) (string, error) {
	switch op {
	case "eq":
		var s string
		_ = json.Unmarshal(raw, &s)
		return fmt.Sprintf("(%s = %s)", expr, c.bind(s)), nil
	case "ne":
		var s string
		_ = json.Unmarshal(raw, &s)
		return fmt.Sprintf("(%s IS DISTINCT FROM %s)", expr, c.bind(s)), nil
	case "contains":
		var s string
		_ = json.Unmarshal(raw, &s)
		return fmt.Sprintf("(%s ILIKE %s)", expr, c.bind("%"+likeEscape(s)+"%")), nil
	case "starts_with":
		var s string
		_ = json.Unmarshal(raw, &s)
		return fmt.Sprintf("(%s ILIKE %s)", expr, c.bind(likeEscape(s)+"%")), nil
	case "matches":
		var s string
		_ = json.Unmarshal(raw, &s)
		// POSIX regex (~, case-sensitive). The pattern is a bound parameter, never inlined.
		return fmt.Sprintf("(%s ~ %s)", expr, c.bind(s)), nil
	case "in":
		var arr []string
		_ = json.Unmarshal(raw, &arr)
		return fmt.Sprintf("(%s = ANY(%s))", expr, c.bind(arr)), nil
	}
	return "", fmt.Errorf("compile: bad string op %q", op)
}

func compileNumberOp(expr, op string, raw json.RawMessage, c *compileCtx) (string, error) {
	cmp := map[string]string{"eq": "=", "ne": "<>", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}
	if op == "in" {
		var arr []json.Number
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.UseNumber()
		_ = d.Decode(&arr)
		nums := make([]float64, 0, len(arr))
		for _, n := range arr {
			f, _ := n.Float64()
			nums = append(nums, f)
		}
		return fmt.Sprintf("(%s = ANY(%s))", expr, c.bind(nums)), nil
	}
	sym, ok := cmp[op]
	if !ok {
		return "", fmt.Errorf("compile: bad number op %q", op)
	}
	var n json.Number
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	_ = d.Decode(&n)
	f, _ := n.Float64()
	return fmt.Sprintf("(%s %s %s)", expr, sym, c.bind(f)), nil
}

func compileBoolOp(expr, op string, raw json.RawMessage, c *compileCtx) (string, error) {
	if op != "eq" {
		return "", fmt.Errorf("compile: bad bool op %q", op)
	}
	var b bool
	_ = json.Unmarshal(raw, &b)
	return fmt.Sprintf("(%s = %s)", expr, c.bind(b)), nil
}

func compileDatetimeOp(expr, op string, raw json.RawMessage, c *compileCtx) (string, error) {
	switch op {
	case "before", "after":
		var s string
		_ = json.Unmarshal(raw, &s)
		t, _ := time.Parse(time.RFC3339, s)
		sym := "<"
		if op == "after" {
			sym = ">"
		}
		return fmt.Sprintf("(%s %s %s)", expr, sym, c.bind(t.UTC())), nil
	case "older_than", "newer_than":
		var s string
		_ = json.Unmarshal(raw, &s)
		d, _ := ParseDuration(s)
		cutoff := time.Now().UTC().Add(-d)
		// older_than: timestamp is before (now - d). newer_than: at/after (now - d).
		sym := "<"
		if op == "newer_than" {
			sym = ">="
		}
		return fmt.Sprintf("(%s %s %s)", expr, sym, c.bind(cutoff)), nil
	}
	return "", fmt.Errorf("compile: bad datetime op %q", op)
}

func compileTagsOp(expr, op string, raw json.RawMessage, c *compileCtx) (string, error) {
	var arr []string
	_ = json.Unmarshal(raw, &arr)
	switch op {
	case "contains_any":
		return fmt.Sprintf("(%s && %s::text[])", expr, c.bind(arr)), nil
	case "contains_all":
		return fmt.Sprintf("(%s @> %s::text[])", expr, c.bind(arr)), nil
	}
	return "", fmt.Errorf("compile: bad tags op %q", op)
}

// versionNormSQL turns a dotted agent_version into an int[] of its leading numeric release
// components for correct numeric ordering (so 1.2.10 > 1.2.9). Any pre-release tag ("-rc1")
// and build metadata ("+...") are stripped; non-numeric components read as 0. This is the
// SQL mirror of internal/version.Compare's release-component ordering; pre-release ordering
// is not represented in SQL (documented limitation). %s is the raw version SQL expression.
func versionNormSQL(expr string) string {
	// strip leading v/V, drop +meta and -pre, keep digits and dots, split to int[].
	return `string_to_array(
		regexp_replace(
			regexp_replace(
				regexp_replace(COALESCE(` + expr + `, ''), '^[vV]', ''),
			'[-+].*$', ''),
		'[^0-9.]', '', 'g'),
	'.')::int[]`
}

func compileVersionOp(expr, op string, raw json.RawMessage, c *compileCtx) (string, error) {
	var s string
	_ = json.Unmarshal(raw, &s)
	left := versionNormSQL(expr)
	right := versionNormSQL(c.bind(s))
	cmp := map[string]string{"eq": "=", "ne": "<>", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}
	sym, ok := cmp[op]
	if !ok {
		return "", fmt.Errorf("compile: bad version op %q", op)
	}
	// Postgres compares int[] element-wise then by length, which is exactly release-component
	// version ordering once each side is normalised to a numeric array.
	return fmt.Sprintf("(%s %s %s)", left, sym, right), nil
}

// compileAttrLeaf compiles an attr.<key> leaf. The key is a bound parameter (never inlined),
// and the stored JSONB value is compared with a cast chosen by the operator. The correlated
// subquery matches the single device_attributes row for the key on the current device.
func (r *Rule) compileAttrLeaf(lf *leaf, c *compileCtx) (string, error) {
	key := strings.TrimPrefix(lf.Field, "attr.")
	keyParam := c.bind(key)
	base := func(cond string) string {
		return fmt.Sprintf("EXISTS (SELECT 1 FROM device_attributes da WHERE da.device_id = d.id AND da.key = %s%s)", keyParam, cond)
	}
	switch lf.Op {
	case "exists":
		return base(""), nil
	case "missing":
		return "(NOT " + base("") + ")", nil
	}

	switch lf.Op {
	case "eq", "ne", "contains", "starts_with", "matches", "in":
		valExpr := "(da.value #>> '{}')"
		if lf.Op == "ne" {
			// ne is true when the device has NO row for this key with that value (so it is
			// also true when the key is absent entirely).
			return "(NOT " + base(fmt.Sprintf(" AND %s = %s", valExpr, c.bind(mustString(lf.Value)))) + ")", nil
		}
		cond, err := attrScalarCond(valExpr, lf.Op, lf.Value, c)
		if err != nil {
			return "", err
		}
		return base(" AND " + cond), nil
	case "lt", "lte", "gt", "gte":
		valExpr := "(da.value)::numeric"
		sym := map[string]string{"lt": "<", "lte": "<=", "gt": ">", "gte": ">="}[lf.Op]
		var n json.Number
		d := json.NewDecoder(strings.NewReader(string(lf.Value)))
		d.UseNumber()
		_ = d.Decode(&n)
		f, _ := n.Float64()
		return base(fmt.Sprintf(" AND jsonb_typeof(da.value) = 'number' AND %s %s %s", valExpr, sym, c.bind(f))), nil
	case "before", "after", "older_than", "newer_than":
		valExpr := "((da.value #>> '{}')::timestamptz)"
		cond, err := attrDatetimeCond(valExpr, lf.Op, lf.Value, c)
		if err != nil {
			return "", err
		}
		return base(" AND jsonb_typeof(da.value) = 'string' AND " + cond), nil
	}
	return "", fmt.Errorf("compile: unsupported attr op %q", lf.Op)
}

func mustString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return strings.Trim(string(raw), `"`)
	}
	return s
}

func attrScalarCond(valExpr, op string, raw json.RawMessage, c *compileCtx) (string, error) {
	switch op {
	case "eq":
		return fmt.Sprintf("%s = %s", valExpr, c.bind(mustString(raw))), nil
	case "contains":
		return fmt.Sprintf("%s ILIKE %s", valExpr, c.bind("%"+likeEscape(mustString(raw))+"%")), nil
	case "starts_with":
		return fmt.Sprintf("%s ILIKE %s", valExpr, c.bind(likeEscape(mustString(raw))+"%")), nil
	case "matches":
		return fmt.Sprintf("%s ~ %s", valExpr, c.bind(mustString(raw))), nil
	case "in":
		var arr []string
		if err := json.Unmarshal(raw, &arr); err != nil {
			var nums []json.Number
			d := json.NewDecoder(strings.NewReader(string(raw)))
			d.UseNumber()
			if err2 := d.Decode(&nums); err2 == nil {
				for _, n := range nums {
					arr = append(arr, n.String())
				}
			}
		}
		return fmt.Sprintf("%s = ANY(%s)", valExpr, c.bind(arr)), nil
	}
	return "", fmt.Errorf("compile: bad attr scalar op %q", op)
}

func attrDatetimeCond(valExpr, op string, raw json.RawMessage, c *compileCtx) (string, error) {
	switch op {
	case "before", "after":
		var s string
		_ = json.Unmarshal(raw, &s)
		t, _ := time.Parse(time.RFC3339, s)
		sym := "<"
		if op == "after" {
			sym = ">"
		}
		return fmt.Sprintf("%s %s %s", valExpr, sym, c.bind(t.UTC())), nil
	case "older_than", "newer_than":
		var s string
		_ = json.Unmarshal(raw, &s)
		d, _ := ParseDuration(s)
		cutoff := time.Now().UTC().Add(-d)
		sym := "<"
		if op == "newer_than" {
			sym = ">="
		}
		return fmt.Sprintf("%s %s %s", valExpr, sym, c.bind(cutoff)), nil
	}
	return "", fmt.Errorf("compile: bad attr datetime op %q", op)
}

// likeEscape escapes LIKE/ILIKE metacharacters so a value with % or _ matches literally.
func likeEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}
