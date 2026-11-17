package workflows

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ValidationError is a workflow definition validation failure (maps to HTTP 400).
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

// IsValidationError reports whether err is a workflow validation error.
func IsValidationError(err error) bool {
	_, ok := err.(*ValidationError)
	return ok
}

func verr(format string, a ...any) *ValidationError {
	return &ValidationError{msg: fmt.Sprintf(format, a...)}
}

const (
	maxActionsPerBranch = 32
	maxTagLen           = 64
	maxSubjectLen       = 512
	maxFilterKeys       = 16
)

// validRings is the fixed allowlist of deployment rings an action may set.
var validRings = map[string]bool{"CANARY": true, "PILOT": true, "PRODUCTION": true}

// ValidateDefinition checks a workflow is well-formed BEFORE it is stored. ruleValidator, when
// non-nil, validates the condition rule (grouprule.Parse). isKnownAction reports whether an
// action type is registered (built-in or via the action registry) so a workflow cannot
// reference an action the engine cannot run.
func ValidateDefinition(w *Workflow, ruleValidator func(json.RawMessage) error, isKnownAction func(ActionType) bool) error {
	if strings.TrimSpace(w.Name) == "" {
		return verr("workflow name is required")
	}
	if len(w.Name) > 128 {
		return verr("workflow name too long")
	}
	// Exactly one of trigger / schedule.
	if (w.Trigger == nil) == (w.Schedule == nil) {
		return verr("a workflow must have exactly one of an event trigger or a schedule")
	}
	if w.Trigger != nil {
		if !w.Trigger.Kind.Valid() {
			return verr("unknown event trigger kind %q", w.Trigger.Kind)
		}
		if len(w.Trigger.Filter) > maxFilterKeys {
			return verr("trigger filter has too many keys")
		}
	}
	if w.Schedule != nil {
		if err := ValidateCron(w.Schedule.Cron); err != nil {
			return verr("invalid schedule cron: %v", err)
		}
		switch w.Schedule.TargetKind {
		case TargetGroup:
			if strings.TrimSpace(w.Schedule.TargetGroup) == "" {
				return verr("schedule group target requires a group id")
			}
		case TargetTags:
			if len(w.Schedule.TargetTags) == 0 {
				return verr("schedule tags target requires at least one tag")
			}
		case TargetRing:
			if !validRings[strings.ToUpper(strings.TrimSpace(w.Schedule.TargetRing))] {
				return verr("schedule ring target must be CANARY, PILOT or PRODUCTION")
			}
		default:
			return verr("schedule target must be group, tags or ring")
		}
	}
	if ruleValidator != nil && len(w.Condition) > 0 {
		if err := ruleValidator(w.Condition); err != nil {
			return verr("invalid condition: %v", err)
		}
	}
	if len(w.ThenActions) == 0 && len(w.ElseActions) == 0 {
		return verr("a workflow must have at least one then or else action")
	}
	if err := validateActions(w.ThenActions, isKnownAction); err != nil {
		return err
	}
	if err := validateActions(w.ElseActions, isKnownAction); err != nil {
		return err
	}
	if w.CooldownSeconds < 0 {
		return verr("cooldown cannot be negative")
	}
	return nil
}

func validateActions(as []Action, isKnownAction func(ActionType) bool) error {
	if len(as) > maxActionsPerBranch {
		return verr("too many actions in one branch (max %d)", maxActionsPerBranch)
	}
	known := isKnownAction
	if known == nil {
		known = func(t ActionType) bool { return knownActionTypes[t] }
	}
	for i, a := range as {
		if !known(a.Type) {
			return verr("action %d: unknown action type %q", i, a.Type)
		}
		if err := validateAction(a); err != nil {
			return verr("action %d (%s): %v", i, a.Type, err)
		}
	}
	return nil
}

func validateAction(a Action) error {
	switch a.Type {
	case ActionAddTag, ActionRemoveTag:
		if strings.TrimSpace(a.Tag) == "" {
			return fmt.Errorf("tag is required")
		}
		if len(a.Tag) > maxTagLen {
			return fmt.Errorf("tag too long")
		}
	case ActionSetRing:
		if !validRings[strings.ToUpper(strings.TrimSpace(a.Ring))] {
			return fmt.Errorf("ring must be CANARY, PILOT or PRODUCTION")
		}
	case ActionGroupInclude, ActionGroupExclude:
		if strings.TrimSpace(a.GroupID) == "" {
			return fmt.Errorf("group_id is required")
		}
	case ActionRunScript:
		if strings.TrimSpace(a.ScriptID) == "" {
			return fmt.Errorf("script_id is required")
		}
		if a.ScriptVersion < 0 {
			return fmt.Errorf("script_version cannot be negative")
		}
	case ActionSendAlert:
		if strings.TrimSpace(a.Subject) == "" {
			return fmt.Errorf("subject is required")
		}
		if len(a.Subject) > maxSubjectLen {
			return fmt.Errorf("subject too long")
		}
	case ActionLock:
		// message optional
	case ActionQuarantine:
		// quarantine tag comes from settings, no args
	case ActionRequireApproval:
		// no args; pause semantics handled by engine
	default:
		// a registry action: no built-in arg checks (the executor validates its own args).
	}
	return nil
}

// FilterMatches reports whether an event's fields satisfy a trigger filter. An empty filter
// matches everything. Each filter entry must equal the corresponding event field. Comparison
// is done on the JSON-normalised string form so 5 and "5" and urgency "high" compare
// predictably regardless of how the event producer typed the value.
func FilterMatches(filter map[string]any, fields map[string]any) bool {
	if len(filter) == 0 {
		return true
	}
	for k, want := range filter {
		got, ok := fields[k]
		if !ok {
			return false
		}
		if normValue(want) != normValue(got) {
			return false
		}
	}
	return true
}

// normValue renders a scalar JSON value to a canonical comparable string. Numbers are
// compared by their numeric value (so 5 == 5.0), everything else by its string form.
func normValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case json.Number:
		if f, err := t.Float64(); err == nil {
			return trimNumber(f)
		}
		return t.String()
	case float64:
		return trimNumber(t)
	case int:
		return trimNumber(float64(t))
	case int64:
		return trimNumber(float64(t))
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func trimNumber(f float64) string {
	s := fmt.Sprintf("%g", f)
	return s
}
