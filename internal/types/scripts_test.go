package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScriptParamNameRule(t *testing.T) {
	good := []string{"X", "PORT", "DB_HOST", "A1_B2", strings.Repeat("A", 32)}
	bad := []string{"", "lower", "1LEAD", "WITH-DASH", "WITH SPACE", strings.Repeat("A", 33), "x"}
	for _, g := range good {
		if !ValidScriptParamName(g) {
			t.Errorf("param name %q should be valid", g)
		}
	}
	for _, b := range bad {
		if ValidScriptParamName(b) {
			t.Errorf("param name %q should be invalid", b)
		}
	}
}

func TestSensorNameRule(t *testing.T) {
	if !ValidSensorName("disk_health") || !ValidSensorName("a") {
		t.Fatal("valid sensor names rejected")
	}
	for _, b := range []string{"", "Disk", "1x", "has.dot", "has-dash", strings.Repeat("a", 49)} {
		if ValidSensorName(b) {
			t.Errorf("sensor name %q should be invalid", b)
		}
	}
}

func TestInterpreterAllowlist(t *testing.T) {
	if p, ok := InterpreterPath(InterpreterBash); !ok || p != "/bin/bash" {
		t.Fatalf("bash path = %q ok=%v", p, ok)
	}
	if p, ok := InterpreterPath(InterpreterPython3); !ok || p != "/usr/bin/python3" {
		t.Fatalf("python3 path = %q ok=%v", p, ok)
	}
	for _, bad := range []ScriptInterpreter{"sh", "/bin/sh", "perl", "ruby", "node", ""} {
		if ValidInterpreter(bad) {
			t.Errorf("interpreter %q must be rejected", bad)
		}
	}
}

func TestParamValueValidation(t *testing.T) {
	cases := []struct {
		t    ScriptParamType
		v    string
		ok   bool
	}{
		{ScriptParamInteger, "42", true},
		{ScriptParamInteger, "-7", true},
		{ScriptParamInteger, "x", false},
		{ScriptParamInteger, "1.5", false},
		{ScriptParamBoolean, "true", true},
		{ScriptParamBoolean, "false", true},
		{ScriptParamBoolean, "1", false},
		{ScriptParamString, "anything $(whoami)", true},
	}
	for _, c := range cases {
		err := ValidateScriptParamValue(c.t, c.v)
		if (err == nil) != c.ok {
			t.Errorf("ValidateScriptParamValue(%s,%q) err=%v, wantOK=%v", c.t, c.v, err, c.ok)
		}
	}
}

func TestComputeScriptSHA256Stable(t *testing.T) {
	a := ComputeScriptSHA256("echo hi\n")
	b := ComputeScriptSHA256("echo hi\n")
	c := ComputeScriptSHA256("echo hi")
	if a != b {
		t.Fatal("sha256 not stable for identical content")
	}
	if a == c {
		t.Fatal("sha256 collided for different content")
	}
	if len(a) != 64 {
		t.Fatalf("sha256 hex length = %d, want 64", len(a))
	}
}

func TestParseSensorValueTyping(t *testing.T) {
	mustParse := func(rt SensorReturnType, raw string) DeviceAttribute {
		a, err := ParseSensorValue("s", rt, raw)
		if err != nil {
			t.Fatalf("ParseSensorValue(%s,%q) err=%v", rt, raw, err)
		}
		if a.Key != "sensor.s" {
			t.Fatalf("key = %q, want sensor.s", a.Key)
		}
		if err := a.Validate(); err != nil {
			t.Fatalf("parsed attribute invalid: %v", err)
		}
		return a
	}
	mustParse(SensorString, "  hello  ")
	if v := mustParse(SensorInteger, " 123 "); string(v.Value) != "123" {
		t.Fatalf("int value = %s", v.Value)
	}
	mustParse(SensorBoolean, "yes")
	mustParse(SensorDatetime, "2026-01-02T03:04:05Z")
	j := mustParse(SensorJSON, `{"a":1}`)
	var m map[string]int
	if err := json.Unmarshal(j.Value, &m); err != nil || m["a"] != 1 {
		t.Fatalf("json value = %s err=%v", j.Value, err)
	}

	// Parse failures keep the last good value (returned as error).
	for _, bad := range []struct {
		rt  SensorReturnType
		raw string
	}{
		{SensorInteger, "not-a-number"},
		{SensorDatetime, "yesterday"},
		{SensorJSON, "{bad json"},
	} {
		if _, err := ParseSensorValue("s", bad.rt, bad.raw); err == nil {
			t.Errorf("ParseSensorValue(%s,%q) should fail", bad.rt, bad.raw)
		}
	}
}

func TestSensorIntervalFloor(t *testing.T) {
	s := &Sensor{Name: "ok", ReturnType: SensorInteger, IntervalSeconds: 60, ScriptVersionID: "v"}
	if err := s.Validate(); err == nil {
		t.Fatal("interval below 15 minutes must be rejected")
	}
	s.IntervalSeconds = SensorMinIntervalSeconds
	if err := s.Validate(); err != nil {
		t.Fatalf("15-minute interval should be valid: %v", err)
	}
}
