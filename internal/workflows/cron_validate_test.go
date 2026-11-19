package workflows

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseCron_Valid(t *testing.T) {
	cases := []string{"* * * * *", "0 9 * * 1-5", "30 15 * * 2,4", "*/15 * * * *", "0 0 1 1 *"}
	for _, c := range cases {
		if _, err := ParseCron(c); err != nil {
			t.Errorf("ParseCron(%q) unexpected error: %v", c, err)
		}
	}
}

func TestParseCron_Invalid(t *testing.T) {
	cases := []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 32 * *", "* * * 13 *", "a * * * *", "*/0 * * * *", "5-2 * * * *"}
	for _, c := range cases {
		if _, err := ParseCron(c); err == nil {
			t.Errorf("ParseCron(%q) expected error, got nil", c)
		}
	}
}

func TestCronMatches(t *testing.T) {
	c, err := ParseCron("30 9 * * *")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Matches(time.Date(2026, 3, 4, 9, 30, 0, 0, time.UTC)) {
		t.Errorf("09:30 should match")
	}
	if c.Matches(time.Date(2026, 3, 4, 9, 31, 0, 0, time.UTC)) {
		t.Errorf("09:31 should not match")
	}
	// weekday range: Mon-Fri at any minute
	wd, _ := ParseCron("* * * * 1-5")
	if !wd.Matches(time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)) { // Thu
		t.Errorf("Thursday should match 1-5")
	}
	if wd.Matches(time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC)) { // Sat
		t.Errorf("Saturday should not match 1-5")
	}
	// Sunday as 0 and 7
	sun0, _ := ParseCron("0 0 * * 0")
	sun7, _ := ParseCron("0 0 * * 7")
	sunday := time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC) // Sunday
	if !sun0.Matches(sunday) || !sun7.Matches(sunday) {
		t.Errorf("both 0 and 7 should match Sunday")
	}
}

func TestFilterMatches(t *testing.T) {
	// empty filter matches anything
	if !FilterMatches(nil, map[string]any{"a": 1}) {
		t.Errorf("nil filter should match")
	}
	// exact string
	if !FilterMatches(map[string]any{"urgency": "high"}, map[string]any{"urgency": "high"}) {
		t.Errorf("string eq should match")
	}
	if FilterMatches(map[string]any{"urgency": "high"}, map[string]any{"urgency": "medium"}) {
		t.Errorf("string mismatch should not match")
	}
	// numeric normalization: 5 (json.Number) == "5"
	if !FilterMatches(map[string]any{"n": "5"}, map[string]any{"n": json.Number("5")}) {
		t.Errorf("5 should match \"5\" across types")
	}
	// missing key
	if FilterMatches(map[string]any{"k": "v"}, map[string]any{"other": "v"}) {
		t.Errorf("missing key should not match")
	}
}

func okKnown(ActionType) bool { return true }

func TestValidateDefinition(t *testing.T) {
	good := &Workflow{
		Name:        "ok",
		Trigger:     &Trigger{Kind: EventCVEMatched},
		ThenActions: []Action{{Type: ActionAddTag, Tag: "x"}},
	}
	if err := ValidateDefinition(good, nil, okKnown); err != nil {
		t.Fatalf("good workflow should validate: %v", err)
	}

	// both trigger and schedule -> error
	bothTS := &Workflow{
		Name:        "x", Trigger: &Trigger{Kind: EventCVEMatched},
		Schedule:    &Schedule{Cron: "* * * * *", TargetKind: TargetTags, TargetTags: []string{"a"}},
		ThenActions: []Action{{Type: ActionAddTag, Tag: "x"}},
	}
	if err := ValidateDefinition(bothTS, nil, okKnown); err == nil {
		t.Errorf("trigger+schedule must be rejected")
	}

	// neither -> error
	neither := &Workflow{Name: "x", ThenActions: []Action{{Type: ActionAddTag, Tag: "x"}}}
	if err := ValidateDefinition(neither, nil, okKnown); err == nil {
		t.Errorf("no trigger/schedule must be rejected")
	}

	// no actions -> error
	noAct := &Workflow{Name: "x", Trigger: &Trigger{Kind: EventCVEMatched}}
	if err := ValidateDefinition(noAct, nil, okKnown); err == nil {
		t.Errorf("no actions must be rejected")
	}

	// bad ring -> error, and IsValidationError true
	badRing := &Workflow{Name: "x", Trigger: &Trigger{Kind: EventCVEMatched}, ThenActions: []Action{{Type: ActionSetRing, Ring: "BOGUS"}}}
	err := ValidateDefinition(badRing, nil, okKnown)
	if err == nil || !IsValidationError(err) {
		t.Errorf("bad ring must be a validation error, got %v", err)
	}

	// unknown action type (not registered) -> error
	unknown := &Workflow{Name: "x", Trigger: &Trigger{Kind: EventCVEMatched}, ThenActions: []Action{{Type: ActionType("nope")}}}
	if err := ValidateDefinition(unknown, nil, func(ActionType) bool { return false }); err == nil {
		t.Errorf("unknown action type must be rejected")
	}

	// invalid cron in schedule -> error
	badCron := &Workflow{Name: "x", Schedule: &Schedule{Cron: "bad", TargetKind: TargetTags, TargetTags: []string{"a"}}, ThenActions: []Action{{Type: ActionAddTag, Tag: "x"}}}
	if err := ValidateDefinition(badCron, nil, okKnown); err == nil {
		t.Errorf("invalid cron must be rejected")
	}
}
