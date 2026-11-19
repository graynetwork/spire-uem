package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/spire-uem/spire-uem/internal/api"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func checkinResp(t *testing.T, router chi.Router, token, hw string) types.CheckinResponse {
	t.Helper()
	body, _ := json.Marshal(types.CheckinRequest{HardwareUUID: hw})
	r := httptest.NewRequest(http.MethodPost, "http://x/api/v1/desktop/checkin", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("check-in returned %d: %s", w.Code, w.Body.String())
	}
	var resp types.CheckinResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// A quarantined device receives only the policies marked allowed_in_quarantine; every other
// policy stays in the list (so the agent's orphan cleanup does not treat it as removed) but
// flagged, script payloads are blanked, and sealed network secrets are withheld even for an
// allowed network profile. Releasing restores normal delivery.
func TestCheckin_QuarantinedDeviceGetsOnlyAllowedPolicies(t *testing.T) {
	pool := invCheckinPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	router := chi.NewRouter()
	api.RegisterRoutes(router, repo, nil)

	uniq := fmt.Sprintf("%d", time.Now().UnixNano())
	hw := "quar-checkin-" + uniq
	devID, token := approveAndClaim(t, ctx, repo, hw)
	tag := "qtest-" + uniq
	if _, err := repo.UpdateDeviceTags(ctx, devID, []string{tag}); err != nil {
		t.Fatal(err)
	}

	mk := func(name string, typ types.PolicyType, payload string) *types.Policy {
		p, err := repo.CreatePolicy(ctx, name+uniq, "", typ, json.RawMessage(payload), []string{tag})
		if err != nil {
			t.Fatalf("create policy %s: %v", name, err)
		}
		return p
	}
	allowed := mk("allowed-dconf", types.PolicyTypeDconfSetting, `{"file_name":"allowed"}`)
	blocked := mk("blocked-dconf", types.PolicyTypeDconfSetting, `{"file_name":"blocked"}`)
	script := mk("blocked-script", types.PolicyTypeScriptPolicy, `{"detect_version_id":"00000000-0000-0000-0000-000000000000","params":{"k":"v"}}`)
	secretPayload := `{"kind":"WIFI","wifi":{"ssid":"Corp","security":"WPA2_PERSONAL","psk":{"ciphertext":"CIPHER-SECRET","encrypted_dek":"d","nonce":"n"}}}`
	wifi := mk("allowed-wifi", types.PolicyTypeNetworkProfile, secretPayload)
	for _, p := range []*types.Policy{allowed, wifi} {
		if _, err := repo.SetPolicyAllowedInQuarantine(ctx, p.ID, true); err != nil {
			t.Fatal(err)
		}
	}

	byID := func(resp types.CheckinResponse) map[string]types.AssignedPolicy {
		m := map[string]types.AssignedPolicy{}
		for _, p := range resp.Policies {
			m[p.ID] = p
		}
		return m
	}

	// Not quarantined: nothing is withheld by quarantine.
	resp := checkinResp(t, router, token, hw)
	for _, p := range resp.Policies {
		if p.QuarantineWithheld {
			t.Fatalf("policy %s flagged quarantine-withheld on a healthy device", p.ID)
		}
	}

	if _, _, err := repo.CreateQuarantine(ctx, devID, "test", "tester", types.QuarantineSourceManual); err != nil {
		t.Fatal(err)
	}
	m := byID(checkinResp(t, router, token, hw))
	for _, p := range []*types.Policy{allowed, blocked, script, wifi} {
		if _, ok := m[p.ID]; !ok {
			t.Fatalf("policy %s missing from the list: a missing policy would be treated as removed by the agent", p.Name)
		}
	}
	if m[allowed.ID].QuarantineWithheld {
		t.Fatal("an allowed-in-quarantine policy was withheld")
	}
	if !m[blocked.ID].QuarantineWithheld {
		t.Fatal("a policy not allowed in quarantine was delivered")
	}
	if !m[script.ID].QuarantineWithheld || strings.TrimSpace(string(m[script.ID].Payload)) != "{}" {
		t.Fatalf("script policy must be withheld with a blank payload, got withheld=%v payload=%s", m[script.ID].QuarantineWithheld, m[script.ID].Payload)
	}
	w := m[wifi.ID]
	if w.QuarantineWithheld {
		t.Fatal("allowed network profile was withheld wholesale")
	}
	if !w.SecretsWithheld || strings.Contains(string(w.Payload), "CIPHER-SECRET") {
		t.Fatalf("sealed network secret leaked to a quarantined device: withheld=%v payload=%s", w.SecretsWithheld, w.Payload)
	}

	// Release: delivery returns to normal.
	if _, err := repo.ReleaseQuarantine(ctx, devID, "tester", "ok"); err != nil {
		t.Fatal(err)
	}
	for _, p := range checkinResp(t, router, token, hw).Policies {
		if p.QuarantineWithheld {
			t.Fatalf("policy %s still withheld after release", p.ID)
		}
	}
}

// Check-in triggers a posture evaluation but never depends on it.
func TestCheckin_EvaluatesPostureWhenHookInstalled(t *testing.T) {
	pool := invCheckinPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	router := chi.NewRouter()
	api.RegisterRoutes(router, repo, nil)
	hw := fmt.Sprintf("posture-hook-%d", time.Now().UnixNano())
	devID, token := approveAndClaim(t, ctx, repo, hw)

	// No hook: check-in works.
	checkinResp(t, router, token, hw)

	called := make(chan string, 4)
	repo.SetPostureHook(func(_ context.Context, id string) { called <- id })
	defer repo.SetPostureHook(nil)
	checkinResp(t, router, token, hw)
	select {
	case id := <-called:
		if id != devID {
			t.Fatalf("hook called for %s, want %s", id, devID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("check-in did not trigger a posture evaluation")
	}

	// A panicking-slow evaluator must not slow the response: the hook runs asynchronously.
	block := make(chan struct{})
	repo.SetPostureHook(func(context.Context, string) { <-block })
	start := time.Now()
	checkinResp(t, router, token, hw)
	if time.Since(start) > 3*time.Second {
		t.Fatal("check-in waited for the posture evaluation")
	}
	close(block)
}
