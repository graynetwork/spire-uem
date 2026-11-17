package grouprule

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustParse(t *testing.T, s string) *Rule {
	t.Helper()
	r, err := Parse(json.RawMessage(s), nil)
	if err != nil {
		t.Fatalf("Parse(%s) unexpected error: %v", s, err)
	}
	return r
}

func TestParse_EmptyIsNilRule(t *testing.T) {
	for _, s := range []string{"", "   ", "null"} {
		r, err := Parse(json.RawMessage(s), nil)
		if err != nil || r != nil {
			t.Fatalf("Parse(%q) = (%v,%v), want (nil,nil)", s, r, err)
		}
	}
}

func TestParse_RejectsUnknownField(t *testing.T) {
	_, err := Parse(json.RawMessage(`{"field":"device.not_a_field","op":"eq","value":"x"}`), nil)
	if !IsValidationError(err) {
		t.Fatalf("unknown field must be a validation error, got %v", err)
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %q, want mention of unknown field", err)
	}
}

func TestParse_RejectsBadOperatorForType(t *testing.T) {
	// contains is not valid for a number field.
	_, err := Parse(json.RawMessage(`{"field":"device.pending_updates","op":"contains","value":"3"}`), nil)
	if !IsValidationError(err) {
		t.Fatalf("bad op for type must be a validation error, got %v", err)
	}
}

func TestParse_RejectsTypeMismatchValue(t *testing.T) {
	// number field with a non-numeric value.
	_, err := Parse(json.RawMessage(`{"field":"device.pending_updates","op":"gt","value":"lots"}`), nil)
	if !IsValidationError(err) {
		t.Fatalf("non-numeric value for number field must be a validation error, got %v", err)
	}
	// boolean field with a string value.
	_, err = Parse(json.RawMessage(`{"field":"device.reboot_required","op":"eq","value":"yes"}`), nil)
	if !IsValidationError(err) {
		t.Fatalf("non-bool value for bool field must be a validation error, got %v", err)
	}
	// datetime field with a non-RFC3339 value.
	_, err = Parse(json.RawMessage(`{"field":"device.last_checkin_at","op":"before","value":"last tuesday"}`), nil)
	if !IsValidationError(err) {
		t.Fatalf("bad datetime value must be a validation error, got %v", err)
	}
}

func TestParse_DepthLimit(t *testing.T) {
	// Build a not-chain deeper than MaxDepth.
	s := `{"field":"device.status","op":"eq","value":"APPROVED"}`
	for i := 0; i < MaxDepth+2; i++ {
		s = `{"not":` + s + `}`
	}
	_, err := Parse(json.RawMessage(s), nil)
	if !IsValidationError(err) || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("over-deep rule must be rejected for nesting, got %v", err)
	}
}

func TestParse_LeafLimit(t *testing.T) {
	leaves := make([]string, 0, MaxLeaves+1)
	for i := 0; i < MaxLeaves+1; i++ {
		leaves = append(leaves, `{"field":"device.status","op":"eq","value":"APPROVED"}`)
	}
	s := `{"all":[` + strings.Join(leaves, ",") + `]}`
	_, err := Parse(json.RawMessage(s), nil)
	if !IsValidationError(err) || !strings.Contains(err.Error(), "conditions") {
		t.Fatalf("over-many leaves must be rejected, got %v", err)
	}
}

func TestParse_RegexValidatorInvoked(t *testing.T) {
	called := false
	_, err := Parse(json.RawMessage(`{"field":"device.hostname","op":"matches","value":"^web-[0-9]+$"}`), func(p string) error {
		called = true
		if p != "^web-[0-9]+$" {
			t.Fatalf("validator got pattern %q", p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("valid regex rejected: %v", err)
	}
	if !called {
		t.Fatal("regex validator was not invoked for a matches operator")
	}
}

func TestParse_RegexRejectedByValidator(t *testing.T) {
	_, err := Parse(json.RawMessage(`{"field":"device.hostname","op":"matches","value":"("}`), func(p string) error {
		return errExample
	})
	if !IsValidationError(err) {
		t.Fatalf("regex rejected by Postgres must surface as a validation error, got %v", err)
	}
}

var errExample = &exampleErr{}

type exampleErr struct{}

func (*exampleErr) Error() string { return "bad pattern" }

func TestParse_NodeMustBeExactlyOneForm(t *testing.T) {
	// both all and a leaf set.
	_, err := Parse(json.RawMessage(`{"all":[{"field":"device.status","op":"eq","value":"APPROVED"}],"field":"device.status","op":"eq","value":"APPROVED"}`), nil)
	if !IsValidationError(err) {
		t.Fatalf("mixed node must be rejected, got %v", err)
	}
}

func TestCompile_ParameterisesSQLLookingValues(t *testing.T) {
	// A value that looks like a SQL injection must be bound, not inlined.
	evil := `'); DROP TABLE devices; --`
	r := mustParse(t, `{"field":"device.hostname","op":"eq","value":`+mustJSON(evil)+`}`)
	sql, args, err := r.Compile(1)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(sql, "DROP TABLE") {
		t.Fatalf("value was inlined into SQL: %s", sql)
	}
	if len(args) != 1 || args[0] != evil {
		t.Fatalf("value not bound as parameter: args=%v", args)
	}
	if !strings.Contains(sql, "$1") {
		t.Fatalf("expected a placeholder in %s", sql)
	}
}

func TestCompile_AttributeKeyIsBound(t *testing.T) {
	r := mustParse(t, `{"field":"attr.hw.cpu_model","op":"eq","value":"Ryzen"}`)
	sql, args, err := r.Compile(1)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Both the key and the value are parameters; the key never appears inline.
	if strings.Contains(sql, "hw.cpu_model") {
		t.Fatalf("attribute key inlined into SQL: %s", sql)
	}
	foundKey, foundVal := false, false
	for _, a := range args {
		if a == "hw.cpu_model" {
			foundKey = true
		}
		if a == "Ryzen" {
			foundVal = true
		}
	}
	if !foundKey || !foundVal {
		t.Fatalf("key/value not both bound: args=%v", args)
	}
}

func TestCompile_EveryOperatorFamilyCompiles(t *testing.T) {
	cases := []string{
		`{"field":"device.hostname","op":"eq","value":"a"}`,
		`{"field":"device.hostname","op":"ne","value":"a"}`,
		`{"field":"device.hostname","op":"contains","value":"a"}`,
		`{"field":"device.hostname","op":"starts_with","value":"a"}`,
		`{"field":"device.hostname","op":"in","value":["a","b"]}`,
		`{"field":"device.hostname","op":"matches","value":"^a"}`,
		`{"field":"device.pending_updates","op":"gte","value":5}`,
		`{"field":"device.pending_updates","op":"in","value":[1,2,3]}`,
		`{"field":"device.reboot_required","op":"eq","value":true}`,
		`{"field":"device.last_checkin_at","op":"older_than","value":"7d"}`,
		`{"field":"device.last_checkin_at","op":"before","value":"2025-01-01T00:00:00Z"}`,
		`{"field":"device.tags","op":"contains_any","value":["prod","eng"]}`,
		`{"field":"device.tags","op":"contains_all","value":["prod","eng"]}`,
		`{"field":"device.agent_version","op":"gte","value":"1.2.0"}`,
		`{"field":"device.agent_version","op":"lt","value":"2.0.0"}`,
		`{"field":"cve.id","op":"exists"}`,
		`{"field":"cve.open_high_or_critical","op":"gt","value":0}`,
		`{"field":"device.compliance","op":"eq","value":true}`,
		`{"field":"attr.sensor.disk_ok","op":"eq","value":false}`,
		`{"field":"attr.hw.mem_mb","op":"gte","value":8192}`,
		`{"field":"attr.custom.key","op":"exists"}`,
		`{"field":"attr.custom.key","op":"missing"}`,
	}
	for _, c := range cases {
		r := mustParse(t, c)
		if _, _, err := r.Compile(1); err != nil {
			t.Fatalf("compile %s: %v", c, err)
		}
	}
}

func TestCompile_VersionUsesNumericArrayOrdering(t *testing.T) {
	r := mustParse(t, `{"field":"device.agent_version","op":"gte","value":"1.2.0"}`)
	sql, _, err := r.Compile(1)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(sql, "int[]") {
		t.Fatalf("version comparison should normalise to int[]: %s", sql)
	}
}

func TestParseDuration(t *testing.T) {
	good := map[string]bool{"7d": true, "12h": true, "30m": true, "2w": true, "45s": true, "1h30m": true}
	for s := range good {
		if _, err := ParseDuration(s); err != nil {
			t.Fatalf("ParseDuration(%q) error: %v", s, err)
		}
	}
	bad := []string{"", "7", "-3d", "0d", "7x", "abc"}
	for _, s := range bad {
		if _, err := ParseDuration(s); err == nil {
			t.Fatalf("ParseDuration(%q) should have failed", s)
		}
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
