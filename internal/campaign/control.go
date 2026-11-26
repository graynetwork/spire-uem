package campaign

// ControlActions lists the operator controls in display order.
var ControlActions = []string{"start", "pause", "resume", "cancel"}

// ControlTransition is the single definition of the admin lifecycle state machine. It returns
// the state the action leads to from the current state, or a refusal message when the action
// is not allowed. The HTTP control endpoint enforces it and the admin page uses it to decide
// which buttons to show, so the two cannot drift apart.
func ControlTransition(action string, from CampaignState) (CampaignState, string) {
	switch action {
	case "start":
		if from != StateDraft && from != StatePaused {
			return "", "campaign cannot be started from " + string(from)
		}
		return StateRunning, ""
	case "pause":
		if from != StateRunning {
			return "", "only a running campaign can be paused"
		}
		return StatePaused, ""
	case "resume":
		// Resume clears a halt as well as a pause. It never revives a finished campaign.
		if from != StatePaused && from != StateHalted {
			return "", "campaign cannot be resumed from " + string(from)
		}
		return StateRunning, ""
	case "cancel":
		if from == StateCompleted || from == StateCancelled {
			return "", "campaign is already " + string(from)
		}
		return StateCancelled, ""
	}
	return "", "unknown action"
}

// AllowedControls returns the actions the state machine permits from the given state.
func AllowedControls(from CampaignState) []string {
	var out []string
	for _, a := range ControlActions {
		if _, msg := ControlTransition(a, from); msg == "" {
			out = append(out, a)
		}
	}
	return out
}
