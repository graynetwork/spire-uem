package web

import "testing"

func TestValidateRolloutValues(t *testing.T) {
	ok := []map[string]interface{}{
		{"rollout.minimum_version": "", "rollout.target_version.PRODUCTION": "none"},
		{"rollout.minimum_version": "1.2.0", "rollout.target_version.PRODUCTION": "1.3.0", "rollout.target_version.CANARY": "v1.4.0-rc1"},
	}
	for i, v := range ok {
		if err := validateRolloutValues(v); err != nil {
			t.Errorf("ok case %d: %v", i, err)
		}
	}
	bad := []map[string]interface{}{
		{"rollout.minimum_version": "latest"},                                              // parses as 0, would disable the floor
		{"rollout.target_version.BETA": "1.x"},                                             // malformed
		{"rollout.minimum_version": "2.0.0", "rollout.target_version.PRODUCTION": "1.9.0"}, // target below floor
	}
	for i, v := range bad {
		if err := validateRolloutValues(v); err == nil {
			t.Errorf("bad case %d: expected error", i)
		}
	}
}
